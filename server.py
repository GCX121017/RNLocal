#!/usr/bin/env python3
"""
牵制网络 - 完整功能（持久化 + DDoS熔断 + 页面加密存储）
"""
import asyncio, json, os, uuid, hashlib, time, logging
from datetime import datetime
from pathlib import Path
import sqlite3
from aiohttp import web
from cryptography.fernet import Fernet
import hmac
import aiohttp
from aiohttp import web

# ============================================================
# 日志与路径
# ============================================================
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)-10s] %(levelname)-5s %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger('RN')

BASE_DIR = Path(__file__).parent.absolute()
STATIC_DIR = BASE_DIR / 'static'
DB_PATH = BASE_DIR / 'restraint_network.db'

# 密钥加载/生成
KEY_FILE = BASE_DIR / 'encryption.key'
if KEY_FILE.exists():
    with open(KEY_FILE, 'rb') as f:
        ENCRYPTION_KEY = f.read()
    log.info(f"已加载加密密钥: {KEY_FILE}")
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(ENCRYPTION_KEY)
    log.info(f"已生成新的加密密钥: {KEY_FILE}")

INDEX_KEY = b'secure-index-key-32bytes!!!'
TOKEN_KEY_FILE = BASE_DIR / 'token.key'
if TOKEN_KEY_FILE.exists():
    with open(TOKEN_KEY_FILE, 'rb') as f:
        TOKEN_KEY = f.read()
else:
    TOKEN_KEY = Fernet.generate_key()
    with open(TOKEN_KEY_FILE, 'wb') as f:
        f.write(TOKEN_KEY)

CIPHER = Fernet(ENCRYPTION_KEY)
TOKEN_CIPHER = Fernet(TOKEN_KEY)

# ============================================================
# 加密页面模板
# ============================================================
LOGIN_PAGE_HTML = '''
<div class="card">
    <h3>登录 / 注册</h3>
    <form data-action="login">
        <input name="username" placeholder="用户名" required />
        <input name="password" type="password" placeholder="密码" required />
        <button type="submit">登录</button>
    </form>
    <form data-action="register">
        <input name="username" placeholder="用户名" required />
        <input name="password" type="password" placeholder="密码" required />
        <button type="submit">注册</button>
    </form>
    <div id="authMsg" style="color: red;"></div>
</div>
'''

MAIN_PAGE_HTML = '''
<div class="card">
    <div id="usernameDisplay" style="font-weight:bold; margin-bottom:0.5rem;"></div>
    <button data-action="logout">退出</button>
</div>
<form data-action="create_post" style="margin:1rem 0;">
    <input name="content" placeholder="说点什么..." style="flex:1;" required />
    <button type="submit">发帖</button>
</form>
<div id="posts"></div>
'''

# ============================================================
# Refrigerator (SQLite)
# ============================================================
class Refrigerator:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = asyncio.Lock()
        self._create_tables()
        log.info("Refrigerator 初始化完成")

    def _create_tables(self):
        self.conn.executescript('''
            CREATE TABLE IF NOT EXISTS blobs (
                blob_id TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS user_index (
                username_hmac TEXT PRIMARY KEY,
                blob_id TEXT NOT NULL,
                FOREIGN KEY (blob_id) REFERENCES blobs(blob_id)
            );
            CREATE TABLE IF NOT EXISTS posts (
                post_id TEXT PRIMARY KEY,
                blob_id TEXT NOT NULL,
                created_order INTEGER,
                FOREIGN KEY (blob_id) REFERENCES blobs(blob_id)
            );
            CREATE TABLE IF NOT EXISTS comments (
                comment_id TEXT PRIMARY KEY,
                post_id TEXT NOT NULL,
                blob_id TEXT NOT NULL,
                created_order INTEGER,
                FOREIGN KEY (blob_id) REFERENCES blobs(blob_id)
            );
            CREATE TABLE IF NOT EXISTS likes (
                target_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                PRIMARY KEY (target_id, user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);
            CREATE INDEX IF NOT EXISTS idx_likes_target ON likes(target_id);
        ''')
        self.conn.commit()

    def _hmac(self, value: str) -> str:
        return hmac.new(INDEX_KEY, value.encode(), hashlib.sha256).hexdigest()

    async def store_blob(self, blob_id, data):
        async with self._lock:
            self.conn.execute('INSERT OR REPLACE INTO blobs (blob_id, encrypted_data) VALUES (?,?)', (blob_id, data))
            self.conn.commit()

    async def get_blob(self, blob_id):
        async with self._lock:
            row = self.conn.execute('SELECT encrypted_data FROM blobs WHERE blob_id=?', (blob_id,)).fetchone()
        return row['encrypted_data'] if row else None

    # ---- 用户 ----
    async def store_user(self, username, enc_data):
        blob_id = f"user_{uuid.uuid4().hex[:12]}"
        await self.store_blob(blob_id, enc_data)
        token = self._hmac(username)
        async with self._lock:
            self.conn.execute('INSERT OR REPLACE INTO user_index (username_hmac, blob_id) VALUES (?,?)', (token, blob_id))
            self.conn.commit()
        return blob_id

    async def get_user_by_username(self, username):
        token = self._hmac(username)
        async with self._lock:
            row = self.conn.execute('SELECT blob_id FROM user_index WHERE username_hmac=?', (token,)).fetchone()
        if not row:
            return None, None
        enc = await self.get_blob(row['blob_id'])
        return enc, row['blob_id']

    # ---- 帖子 ----
    async def add_post(self, post_id, enc_data):
        await self.store_blob(post_id, enc_data)
        async with self._lock:
            max_order = self.conn.execute('SELECT COALESCE(MAX(created_order),-1)+1 FROM posts').fetchone()[0]
            self.conn.execute('INSERT INTO posts (post_id, blob_id, created_order) VALUES (?,?,?)', (post_id, post_id, max_order))
            self.conn.commit()

    async def get_post_ids(self):
        async with self._lock:
            rows = self.conn.execute('SELECT post_id FROM posts ORDER BY created_order ASC').fetchall()
        return [r['post_id'] for r in rows]

    # ---- 评论 ----
    async def add_comment(self, comment_id, post_id, enc_data):
        await self.store_blob(comment_id, enc_data)
        async with self._lock:
            max_order = self.conn.execute('SELECT COALESCE(MAX(created_order),-1)+1 FROM comments').fetchone()[0]
            self.conn.execute('INSERT INTO comments (comment_id, post_id, blob_id, created_order) VALUES (?,?,?,?)', (comment_id, post_id, comment_id, max_order))
            self.conn.commit()

    async def get_comment_ids_of_post(self, post_id):
        async with self._lock:
            rows = self.conn.execute('SELECT comment_id FROM comments WHERE post_id=? ORDER BY created_order ASC', (post_id,)).fetchall()
        return [r['comment_id'] for r in rows]

    # ---- 点赞 ----
    async def toggle_like(self, target_id, user_id):
        async with self._lock:
            exist = self.conn.execute('SELECT 1 FROM likes WHERE target_id=? AND user_id=?', (target_id, user_id)).fetchone()
            if exist:
                self.conn.execute('DELETE FROM likes WHERE target_id=? AND user_id=?', (target_id, user_id))
            else:
                self.conn.execute('INSERT INTO likes (target_id, user_id) VALUES (?,?)', (target_id, user_id))
            self.conn.commit()
            count = self.conn.execute('SELECT COUNT(*) FROM likes WHERE target_id=?', (target_id,)).fetchone()[0]
        return count

    async def get_likes_count(self, target_id):
        async with self._lock:
            row = self.conn.execute('SELECT COUNT(*) FROM likes WHERE target_id=?', (target_id,)).fetchone()
        return row[0] if row else 0

    def close(self):
        self.conn.close()

# ============================================================
# Cooker, Cook, Kitchen
# ============================================================
class Cooker:
    def process(self, data, params=None):
        return data

class Cook:
    def __init__(self, fridge, cooker):
        self.fridge = fridge
        self.cooker = cooker

    async def store(self, blob_id, data):
        await self.fridge.store_blob(blob_id, data)

    async def fetch(self, blob_id):
        data = await self.fridge.get_blob(blob_id)
        if data is None:
            raise KeyError(f"Blob {blob_id} not found")
        return data

class Kitchen:
    def __init__(self, cook, fridge):
        self.cook = cook
        self.fridge = fridge

    async def handle_store(self, blob_id, data):
        await self.cook.store(blob_id, data)

    async def handle_fetch(self, blob_id):
        return await self.cook.fetch(blob_id)

    async def store_user(self, username, enc):
        return await self.fridge.store_user(username, enc)

    async def get_user_by_username(self, username):
        return await self.fridge.get_user_by_username(username)

    async def add_post(self, post_id, enc):
        await self.fridge.add_post(post_id, enc)

    async def get_post_ids(self):
        return await self.fridge.get_post_ids()

    async def add_comment(self, cid, pid, enc):
        await self.fridge.add_comment(cid, pid, enc)

    async def get_comment_ids_of_post(self, pid):
        return await self.fridge.get_comment_ids_of_post(pid)

    async def toggle_like(self, target_id, user_id):
        return await self.fridge.toggle_like(target_id, user_id)

    async def get_likes_count(self, target_id):
        return await self.fridge.get_likes_count(target_id)

# ============================================================
# Corridor
# ============================================================
class Corridor:
    def __init__(self, kitchen):
        self.kitchen = kitchen
        self.cipher = CIPHER
        self.token_cipher = TOKEN_CIPHER

    def _encrypt(self, plaintext: str) -> bytes:
        return self.cipher.encrypt(plaintext.encode('utf-8'))

    def _decrypt(self, ciphertext: bytes) -> str:
        return self.cipher.decrypt(ciphertext).decode('utf-8')

    def _generate_token(self, user_id, username):
        payload = json.dumps({'user_id': user_id, 'username': username, 'exp': int(time.time())+86400})
        return self.token_cipher.encrypt(payload.encode()).decode()

    def _verify_token(self, token):
        try:
            plain = self.token_cipher.decrypt(token.encode())
            payload = json.loads(plain)
            if payload.get('exp', 0) < int(time.time()):
                raise ValueError("Token expired")
            return payload
        except Exception:
            raise PermissionError("Invalid token")

    async def get_page(self, page_name, token=None):
        blob_id = f'page:{page_name}'
        enc = await self.kitchen.handle_fetch(blob_id)  # 可能抛出 KeyError
        return self._decrypt(enc)

    # ---- 业务逻辑 ----
    async def register(self, username, password):
        enc_exist, _ = await self.kitchen.get_user_by_username(username)
        if enc_exist:
            raise ValueError("用户名已存在")
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        user_data = json.dumps({'username': username, 'password_hash': pwd_hash})
        enc = self._encrypt(user_data)
        blob_id = await self.kitchen.store_user(username, enc)
        return self._generate_token(blob_id, username)

    async def login(self, username, password):
        enc_data, blob_id = await self.kitchen.get_user_by_username(username)
        if not enc_data:
            raise ValueError("用户名或密码错误")
        user = json.loads(self._decrypt(enc_data))
        if user['password_hash'] != hashlib.sha256(password.encode()).hexdigest():
            raise ValueError("用户名或密码错误")
        return self._generate_token(blob_id, username)

    async def get_user_info(self, token):
        payload = self._verify_token(token)
        return {'username': payload['username'], 'user_id': payload['user_id']}

    async def create_post(self, token, content):
        payload = self._verify_token(token)
        post_id = f"post_{uuid.uuid4().hex[:8]}"
        post_obj = {
            'id': post_id, 'author': payload['username'], 'content': content,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'likes': 0, 'comments': []
        }
        enc = self._encrypt(json.dumps(post_obj, ensure_ascii=False))
        await self.kitchen.add_post(post_id, enc)
        return post_obj

    async def get_posts(self, token):
        self._verify_token(token)
        post_ids = await self.kitchen.get_post_ids()
        posts = []
        for pid in post_ids:
            try:
                enc = await self.kitchen.handle_fetch(pid)
                post = json.loads(self._decrypt(enc))
                post['likes'] = await self.kitchen.get_likes_count(pid)
                comment_ids = await self.kitchen.get_comment_ids_of_post(pid)
                post['comments'] = []
                for cid in comment_ids:
                    try:
                        cenc = await self.kitchen.handle_fetch(cid)
                        cmt = json.loads(self._decrypt(cenc))
                        cmt['likes'] = await self.kitchen.get_likes_count(cid)
                        post['comments'].append(cmt)
                    except Exception:
                        pass
                posts.append(post)
            except Exception:
                pass
        posts.reverse()
        return posts

    async def create_comment(self, token, post_id, content):
        payload = self._verify_token(token)
        cid = f"comment_{uuid.uuid4().hex[:8]}"
        cmt_obj = {
            'id': cid, 'post_id': post_id, 'author': payload['username'], 'content': content,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'likes': 0
        }
        enc = self._encrypt(json.dumps(cmt_obj, ensure_ascii=False))
        await self.kitchen.add_comment(cid, post_id, enc)
        return cmt_obj

    async def toggle_like(self, token, target_id, target_type):
        payload = self._verify_token(token)
        new_count = await self.kitchen.toggle_like(target_id, payload['user_id'])
        return {'target_id': target_id, 'likes': new_count}

# ============================================================
# Waiter (带 DDoS 防护)
# ============================================================
class WaiterServer:
    def __init__(self, corridor):
        self.corridor = corridor
        self.clients = set()
        self.req_times = []
        self.window_size = 1.0
        self.threshold = 100
        self.ddos_active = False
        self.ddos_lock = asyncio.Lock()
        self.ddos_end_time = 0
        log.info("Waiter 初始化完成，DDoS 防护已激活")

    async def _check_ddos(self):
        now = time.time()
        self.req_times = [t for t in self.req_times if now - t < self.window_size]
        self.req_times.append(now)
        if len(self.req_times) > self.threshold and not self.ddos_active:
            await self._activate_ddos()

    async def _activate_ddos(self):
        async with self.ddos_lock:
            if self.ddos_active:
                return
            self.ddos_active = True
            self.ddos_end_time = time.time() + 10
            log.warning("DDoS 攻击检测！熔断激活，断开所有连接")
            maint_msg = json.dumps({"action": "ddos_maintenance"})
            max_ws = list(self.clients)
            for ws in max_ws:
                try:
                    await ws.send_str(maint_msg)
                except Exception:
                    pass
                await ws.close()
            self.clients.clear()
            asyncio.create_task(self._recover_ddos())

    async def _recover_ddos(self):
        await asyncio.sleep(10)
        async with self.ddos_lock:
            self.ddos_active = False
            self.req_times.clear()
            log.info("DDoS 熔断已恢复")

    async def ws_handler(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        if self.ddos_active:
            await ws.send_json({"action": "ddos_maintenance"})
            await ws.close()
            return ws

        self.clients.add(ws)
        client_ip = request.remote
        log.info(f"[W] 新连接: {client_ip} (当前连接数: {len(self.clients)})")

        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await self._check_ddos()
                    if self.ddos_active:
                        try:
                            await ws.send_json({"action": "ddos_maintenance"})
                        except Exception:
                            pass
                        continue

                    try:
                        req = json.loads(msg.data)
                        action = req.get('action', 'unknown')
                        log.info(f"[W] 收到请求: {action} (from {client_ip})")
                        response = await self._handle_action(action, req)
                        if action in ('create_post', 'create_comment', 'toggle_like'):
                            await self._broadcast(response)
                        else:
                            await ws.send_json(response)
                    except json.JSONDecodeError:
                        log.warning("[W] 无效的 JSON")
                        await ws.send_json({'error': '无效的请求格式'})
                    except Exception as e:
                        log.error(f"[W] 处理错误: {e}")
                        await ws.send_json({'error': str(e)})
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    log.error(f"[W] WebSocket 错误: {ws.exception()}")
        finally:
            self.clients.discard(ws)
            log.info(f"[W] 连接断开: {client_ip} (当前连接数: {len(self.clients)})")
        return ws

    async def _handle_action(self, action, req):
        if self.ddos_active:
            return {'action': 'ddos_maintenance'}

        if action == 'get_page':
            page = req.get('page', 'login')
            try:
                html = await self.corridor.get_page(page)
                return {'action': 'render_page', 'html': html, 'page': page}
            except KeyError:
                return {'error': f'页面 {page} 不存在'}
        elif action == 'auto_login':
            try:
                self.corridor._verify_token(req['token'])
                html = await self.corridor.get_page('main')
                return {'action': 'render_page', 'html': html, 'page': 'main'}
            except (PermissionError, KeyError):
                html = await self.corridor.get_page('login')
                return {'action': 'render_page', 'html': html, 'page': 'login'}

        if action == 'register':
            token = await self.corridor.register(req['username'], req['password'])
            return {'action': 'auth_success', 'token': token}
        elif action == 'login':
            token = await self.corridor.login(req['username'], req['password'])
            return {'action': 'auth_success', 'token': token}
        elif action == 'get_user_info':
            info = await self.corridor.get_user_info(req['token'])
            return {'action': 'user_info', **info}
        elif action == 'get_posts':
            posts = await self.corridor.get_posts(req['token'])
            return {'action': 'posts', 'posts': posts}
        elif action == 'create_post':
            post = await self.corridor.create_post(req['token'], req['content'])
            return {'action': 'new_post', 'post': post}
        elif action == 'create_comment':
            comment = await self.corridor.create_comment(req['token'], req['post_id'], req['content'])
            return {'action': 'new_comment', 'comment': comment}
        elif action == 'toggle_like':
            result = await self.corridor.toggle_like(req['token'], req['target_id'], req['target_type'])
            return {'action': 'like_update', **result}
        else:
            log.warning(f"[W] 未知操作: {action}")
            return {'error': f'未知操作: {action}'}

    async def _broadcast(self, message):
        for ws in set(self.clients):
            try:
                await ws.send_json(message)
            except Exception:
                self.clients.discard(ws)

# ============================================================
# 应用初始化
# ============================================================
async def init_app():
    log.info("=" * 50)
    log.info("🔐 牵制网络 启动中...")
    log.info("=" * 50)

    fridge = Refrigerator(DB_PATH)
    cooker = Cooker()
    cook = Cook(fridge, cooker)
    kitchen = Kitchen(cook, fridge)
    corridor = Corridor(kitchen)

    # 预加密页面模板并存入冰箱（如果尚未存储）
    for name, html in [('login', LOGIN_PAGE_HTML), ('main', MAIN_PAGE_HTML)]:
        blob_id = f'page:{name}'
        try:
            await kitchen.handle_fetch(blob_id)
            log.info(f"页面 {name} 已存在，跳过存储")
        except KeyError:
            enc = corridor._encrypt(html)
            await kitchen.handle_store(blob_id, enc)
            log.info(f"页面 {name} 已加密存储")

    waiter = WaiterServer(corridor)

    app = web.Application()
    app.router.add_static('/static', str(STATIC_DIR), name='static')
    async def index(request):
        return web.FileResponse(str(STATIC_DIR / 'index.html'))
    app.router.add_get('/', index)
    app.router.add_get('/ws', waiter.ws_handler)

    async def cleanup(app):
        fridge.close()
        log.info("Refrigerator 已关闭")
    app.on_cleanup.append(cleanup)

    log.info(f"✅ 服务器就绪: http://127.0.0.1:8080")
    log.info(f"DDoS 防护阈值: {waiter.threshold} 请求/秒")
    log.info("=" * 50)
    return app

if __name__ == '__main__':
    app = init_app()
    web.run_app(app, host='127.0.0.1', port=8080)
