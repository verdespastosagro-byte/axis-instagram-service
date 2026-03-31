"""
=============================================================================
  AXIS AI — INSTAGRAM INTEGRATION SERVICE
  Serviço de integração com Instagram via login usuário/senha
  Biblioteca: instagrapi (API Privada Mobile do Instagram)
  Framework: FastAPI + Uvicorn
=============================================================================

SETUP RÁPIDO:
  1. pip install instagrapi fastapi uvicorn python-dotenv cryptography redis pillow moviepy
  2. Copie o .env.example e configure as variáveis
  3. uvicorn instagram_service:app --host 0.0.0.0 --port 8000

ENDPOINTS DISPONÍVEIS:
  POST   /instagram/connect          → Conectar conta Instagram
  POST   /instagram/verify           → Resolver desafio 2FA / checkpoint
  GET    /instagram/status/{user_id} → Status da conexão
  POST   /instagram/post/feed        → Publicar foto no feed
  POST   /instagram/post/carousel    → Publicar carrossel
  POST   /instagram/post/reel        → Publicar Reel
  POST   /instagram/post/story       → Publicar Story
  DELETE /instagram/disconnect/{id}  → Desconectar conta

AUTENTICAÇÃO:
  Todos os requests precisam do header:
    X-API-Key: <valor de API_SECRET_KEY no .env>

=============================================================================
.env.example:
  API_SECRET_KEY=sua_chave_secreta_aqui
  ENCRYPTION_KEY=<gerar com: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
  DATABASE_URL=postgresql://user:pass@host:5432/dbname
  REDIS_URL=redis://localhost:6379
=============================================================================
"""

import os
import json
import uuid
import time
import random
import logging
import asyncio
import hashlib
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, Header, HTTPException, UploadFile, File, Form, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from cryptography.fernet import Fernet

# ─── Tentativa de importar dependências opcionais ────────────────────────────
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logging.warning("redis não instalado. Sessões serão mantidas apenas em memória.")

try:
    from instagrapi import Client
    from instagrapi.exceptions import (
        ChallengeRequired,
        LoginRequired,
        BadPassword,
        InvalidTargetUser,
        ClientError,
        TwoFactorRequired,
    )
    INSTAGRAPI_AVAILABLE = True
except ImportError:
    INSTAGRAPI_AVAILABLE = False
    logging.error("instagrapi não instalado! Execute: pip install instagrapi")

# ─── Config ──────────────────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("axis.instagram")

API_SECRET_KEY = os.getenv("API_SECRET_KEY", "axis-dev-key-change-in-production")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
REDIS_URL      = os.getenv("REDIS_URL", "redis://localhost:6379")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://axis-ai-azure.vercel.app,http://localhost:3000").split(",")

# Fernet para criptografia de sessões
if ENCRYPTION_KEY:
    fernet = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)
else:
    logger.warning("ENCRYPTION_KEY não definida! Gerando chave temporária (NÃO use em produção).")
    _temp_key = Fernet.generate_key()
    fernet = Fernet(_temp_key)
    logger.warning(f"Chave temporária: {_temp_key.decode()} — defina no .env")

# ─── Armazenamento em memória (fallback sem Redis/banco) ─────────────────────
# Em produção, substitua por PostgreSQL + Redis
_sessions_store: dict = {}       # user_id → session_data (criptografado)
_status_store: dict   = {}       # user_id → status info
_clients_cache: dict  = {}       # user_id → Client ativo (cache em memória)
_pending_challenges: dict = {}   # user_id → Client aguardando challenge
_pending_credentials: dict = {}  # user_id → {"username": ..., "password": ...} (temporário durante challenge)

# ─── Redis (opcional) ────────────────────────────────────────────────────────
redis_client = None
if REDIS_AVAILABLE and REDIS_URL:
    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        redis_client.ping()
        logger.info("Conectado ao Redis com sucesso.")
    except Exception as e:
        logger.warning(f"Redis não disponível: {e}. Usando armazenamento em memória.")
        redis_client = None

# ─── Helpers de armazenamento ────────────────────────────────────────────────

def _store_session(user_id: str, session_data: dict):
    """Criptografa e armazena a sessão do Instagram."""
    raw = json.dumps(session_data).encode()
    encrypted = fernet.encrypt(raw).decode()
    if redis_client:
        redis_client.set(f"ig:session:{user_id}", encrypted, ex=60 * 60 * 24 * 30)  # 30 dias
    else:
        _sessions_store[user_id] = encrypted

def _load_session(user_id: str) -> Optional[dict]:
    """Carrega e descriptografa a sessão do Instagram."""
    try:
        if redis_client:
            encrypted = redis_client.get(f"ig:session:{user_id}")
        else:
            encrypted = _sessions_store.get(user_id)
        if not encrypted:
            return None
        raw = fernet.decrypt(encrypted.encode())
        return json.loads(raw)
    except Exception as e:
        logger.error(f"Erro ao carregar sessão de {user_id}: {e}")
        return None

def _store_status(user_id: str, status: dict):
    if redis_client:
        redis_client.set(f"ig:status:{user_id}", json.dumps(status), ex=60 * 60 * 24 * 30)
    else:
        _status_store[user_id] = status

def _load_status(user_id: str) -> Optional[dict]:
    if redis_client:
        raw = redis_client.get(f"ig:status:{user_id}")
        return json.loads(raw) if raw else None
    return _status_store.get(user_id)

def _delete_session(user_id: str):
    if redis_client:
        redis_client.delete(f"ig:session:{user_id}", f"ig:status:{user_id}")
    else:
        _sessions_store.pop(user_id, None)
        _status_store.pop(user_id, None)
    _clients_cache.pop(user_id, None)
    _pending_challenges.pop(user_id, None)
    _pending_credentials.pop(user_id, None)

# ─── Instagram Client helpers ────────────────────────────────────────────────

def _build_client() -> "Client":
    """Cria um Client instagrapi configurado para parecer um device real."""
    cl = Client()
    # Simula Samsung Galaxy S21 — ajuste conforme necessário
    cl.set_device({
        "app_version": "269.0.0.18.75",
        "android_version": 26,
        "android_release": "8.0.0",
        "dpi": "480dpi",
        "resolution": "1080x1920",
        "manufacturer": "Samsung",
        "device": "SM-G991B",
        "model": "samsung",
        "cpu": "qcom",
        "version_code": "301484483",
    })
    cl.delay_range = [1, 3]  # delay aleatório em segundos entre ações
    return cl

def _get_or_restore_client(user_id: str) -> Optional["Client"]:
    """Retorna um Client ativo, restaurando da sessão salva se necessário."""
    if user_id in _clients_cache:
        return _clients_cache[user_id]

    session_data = _load_session(user_id)
    status = _load_status(user_id)
    if not session_data or not status:
        return None

    try:
        cl = _build_client()
        cl.set_settings(session_data)
        cl.login(status["username"], "")  # tenta revalidar sessão sem senha
        _clients_cache[user_id] = cl
        logger.info(f"Sessão restaurada para user_id={user_id}")
        return cl
    except Exception as e:
        logger.warning(f"Sessão expirada para {user_id}: {e}")
        return None

# ─── FastAPI App ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="Axis AI — Instagram Service",
    description="Serviço de integração Instagram via login usuário/senha para o sistema Axis AI.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Autenticação por API Key ────────────────────────────────────────────────

async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_SECRET_KEY:
        raise HTTPException(status_code=401, detail="API Key inválida.")
    return x_api_key

# ─── Schemas ─────────────────────────────────────────────────────────────────

class ConnectRequest(BaseModel):
    user_id: str
    username: str
    password: str

class VerifyRequest(BaseModel):
    user_id: str
    code: str

class FeedPostRequest(BaseModel):
    user_id: str
    caption: str = ""
    image_url: Optional[str] = None  # URL pública da imagem (alternativa ao upload)

class CarouselPostRequest(BaseModel):
    user_id: str
    caption: str = ""
    image_urls: List[str] = []

class ReelPostRequest(BaseModel):
    user_id: str
    caption: str = ""
    video_url: Optional[str] = None

class StoryPostRequest(BaseModel):
    user_id: str
    image_url: Optional[str] = None

# ─── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "instagrapi": INSTAGRAPI_AVAILABLE,
        "redis": redis_client is not None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/instagram/connect", dependencies=[Depends(verify_api_key)])
async def connect_instagram(req: ConnectRequest):
    """
    Conecta uma conta do Instagram via usuário e senha.
    Retorna status 'connected' ou 'challenge_required' (para 2FA/checkpoint).
    """
    if not INSTAGRAPI_AVAILABLE:
        raise HTTPException(status_code=503, detail="instagrapi não instalado no servidor.")

    logger.info(f"Tentativa de login: user_id={req.user_id}, ig_user={req.username}")

    # ── Se já tem challenge pendente em memória, tenta revalidar (usuário aprovou no celular) ──
    existing_cl = _pending_challenges.get(req.user_id)
    if existing_cl:
        try:
            logger.info(f"Recheckando challenge aprovado para user_id={req.user_id}")
            existing_cl.login(req.username, req.password)
            session_data = existing_cl.get_settings()
            _store_session(req.user_id, session_data)
            _store_status(req.user_id, {
                "status": "connected",
                "username": req.username,
                "connected_at": datetime.now(timezone.utc).isoformat(),
                "last_used_at": datetime.now(timezone.utc).isoformat(),
            })
            _clients_cache[req.user_id] = existing_cl
            _pending_challenges.pop(req.user_id, None)
            _pending_credentials.pop(req.user_id, None)
            logger.info(f"Recheck bem-sucedido após aprovação no celular: user_id={req.user_id}")
            return {"status": "connected", "username": req.username}
        except ChallengeRequired:
            # Ainda não aprovado — continua com novo client abaixo
            logger.info(f"Challenge ainda pendente para user_id={req.user_id}")
        except Exception as e:
            logger.warning(f"Recheck falhou: {e}")

    cl = _build_client()

    # Tenta restaurar sessão anterior primeiro
    old_session = _load_session(req.user_id)
    if old_session:
        try:
            cl.set_settings(old_session)
        except Exception:
            pass

    try:
        cl.login(req.username, req.password)

        # Login bem-sucedido — salva sessão (sem senha)
        session_data = cl.get_settings()
        _store_session(req.user_id, session_data)
        _store_status(req.user_id, {
            "status": "connected",
            "username": req.username,
            "connected_at": datetime.now(timezone.utc).isoformat(),
            "last_used_at": datetime.now(timezone.utc).isoformat(),
        })
        _clients_cache[req.user_id] = cl
        _pending_challenges.pop(req.user_id, None)
        _pending_credentials.pop(req.user_id, None)

        logger.info(f"Login bem-sucedido: user_id={req.user_id}")
        return {"status": "connected", "username": req.username}

    except ChallengeRequired:
        logger.info(f"Challenge requerido para user_id={req.user_id}")
        _pending_challenges[req.user_id] = cl
        # Salva credenciais temporariamente para recheck após aprovação no celular
        _pending_credentials[req.user_id] = {"username": req.username, "password": req.password}
        _store_status(req.user_id, {
            "status": "pending_challenge",
            "username": req.username,
            "connected_at": None,
        })

        # Tenta enviar código de verificação automaticamente
        try:
            cl.challenge_resolve(cl.last_json)
        except Exception as e:
            logger.warning(f"Não foi possível enviar challenge automaticamente: {e}")

        return {
            "status": "challenge_required",
            "message": "Verifique seu email ou SMS e informe o código de verificação.",
            "username": req.username,
        }

    except TwoFactorRequired:
        logger.info(f"2FA requerido para user_id={req.user_id}")
        _pending_challenges[req.user_id] = cl
        _pending_credentials[req.user_id] = {"username": req.username, "password": req.password}
        _store_status(req.user_id, {
            "status": "pending_2fa",
            "username": req.username,
            "connected_at": None,
        })
        return {
            "status": "2fa_required",
            "message": "Autenticação de dois fatores ativada. Informe o código do seu app autenticador.",
            "username": req.username,
        }

    except BadPassword:
        raise HTTPException(status_code=401, detail="Usuário ou senha incorretos.")

    except Exception as e:
        logger.error(f"Erro no login de {req.user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Erro ao conectar: {str(e)}")


@app.post("/instagram/verify", dependencies=[Depends(verify_api_key)])
async def verify_challenge(req: VerifyRequest):
    """
    Resolve um challenge de 2FA ou checkpoint com o código recebido pelo usuário.
    """
    cl = _pending_challenges.get(req.user_id)
    if not cl:
        raise HTTPException(
            status_code=400,
            detail="Nenhum challenge pendente para este usuário. Faça o login primeiro."
        )

    try:
        # Resolve 2FA
        try:
            cl.two_factor_login(req.code)
        except Exception:
            # Tenta resolver checkpoint genérico
            cl.challenge_resolve_simple(req.code)

        status = _load_status(req.user_id) or {}
        username = status.get("username", "")

        session_data = cl.get_settings()
        _store_session(req.user_id, session_data)
        _store_status(req.user_id, {
            "status": "connected",
            "username": username,
            "connected_at": datetime.now(timezone.utc).isoformat(),
            "last_used_at": datetime.now(timezone.utc).isoformat(),
        })
        _clients_cache[req.user_id] = cl
        _pending_challenges.pop(req.user_id, None)

        logger.info(f"Challenge resolvido com sucesso para user_id={req.user_id}")
        return {"status": "connected", "username": username}

    except Exception as e:
        logger.error(f"Erro ao resolver challenge de {req.user_id}: {e}")
        raise HTTPException(status_code=400, detail=f"Código inválido ou expirado: {str(e)}")


@app.get("/instagram/status/{user_id}", dependencies=[Depends(verify_api_key)])
async def get_status(user_id: str):
    """Retorna o status da conexão Instagram de um usuário."""
    status = _load_status(user_id)
    if not status:
        return {"status": "disconnected", "user_id": user_id}
    return {"user_id": user_id, **status}


@app.delete("/instagram/disconnect/{user_id}", dependencies=[Depends(verify_api_key)])
async def disconnect(user_id: str):
    """Remove a sessão e desconecta a conta Instagram."""
    cl = _clients_cache.get(user_id)
    if cl:
        try:
            cl.logout()
        except Exception:
            pass
    _delete_session(user_id)
    logger.info(f"Conta desconectada: user_id={user_id}")
    return {"status": "disconnected", "user_id": user_id}


# ─── Helpers de publicação ───────────────────────────────────────────────────

async def _download_to_temp(url: str, suffix: str) -> str:
    """Baixa uma URL para um arquivo temporário e retorna o caminho."""
    import urllib.request
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    urllib.request.urlretrieve(url, tmp.name)
    return tmp.name

def _require_client(user_id: str) -> "Client":
    cl = _get_or_restore_client(user_id)
    if not cl:
        raise HTTPException(
            status_code=401,
            detail="Conta Instagram não conectada ou sessão expirada. Reconecte a conta."
        )
    return cl

def _update_last_used(user_id: str):
    status = _load_status(user_id) or {}
    status["last_used_at"] = datetime.now(timezone.utc).isoformat()
    _store_status(user_id, status)


# ─── Publicação: Feed (foto única) ──────────────────────────────────────────

@app.post("/instagram/post/feed", dependencies=[Depends(verify_api_key)])
async def post_feed(
    user_id: str = Form(...),
    caption: str = Form(""),
    image: UploadFile = File(None),
    image_url: str = Form(None),
):
    """Publica uma foto no feed do Instagram."""
    cl = _require_client(user_id)
    tmp_path = None

    try:
        if image:
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
            tmp.write(await image.read())
            tmp.close()
            tmp_path = tmp.name
        elif image_url:
            tmp_path = await _download_to_temp(image_url, ".jpg")
        else:
            raise HTTPException(status_code=400, detail="Envie uma imagem ou image_url.")

        time.sleep(random.uniform(1, 3))
        media = cl.photo_upload(path=tmp_path, caption=caption)
        _update_last_used(user_id)

        logger.info(f"Feed publicado para user_id={user_id}, media_id={media.id}")
        return {
            "status": "published",
            "media_id": str(media.id),
            "media_type": "feed",
            "caption": caption,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao publicar feed para {user_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ─── Publicação: Carrossel ──────────────────────────────────────────────────

@app.post("/instagram/post/carousel", dependencies=[Depends(verify_api_key)])
async def post_carousel(
    user_id: str = Form(...),
    caption: str = Form(""),
    images: List[UploadFile] = File(None),
    image_urls: str = Form(None),  # JSON array de URLs
):
    """Publica um carrossel (múltiplas imagens) no feed do Instagram."""
    cl = _require_client(user_id)
    tmp_paths = []

    try:
        if images:
            for img in images:
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
                tmp.write(await img.read())
                tmp.close()
                tmp_paths.append(tmp.name)
        elif image_urls:
            urls = json.loads(image_urls)
            for url in urls:
                tmp_paths.append(await _download_to_temp(url, ".jpg"))
        else:
            raise HTTPException(status_code=400, detail="Envie imagens ou image_urls.")

        if len(tmp_paths) < 2:
            raise HTTPException(status_code=400, detail="Carrossel requer pelo menos 2 imagens.")

        time.sleep(random.uniform(1, 3))
        media = cl.album_upload(paths=tmp_paths, caption=caption)
        _update_last_used(user_id)

        logger.info(f"Carrossel publicado para user_id={user_id}, media_id={media.id}")
        return {
            "status": "published",
            "media_id": str(media.id),
            "media_type": "carousel",
            "slides": len(tmp_paths),
            "caption": caption,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao publicar carrossel para {user_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        for p in tmp_paths:
            if os.path.exists(p):
                os.unlink(p)


# ─── Publicação: Reel ───────────────────────────────────────────────────────

@app.post("/instagram/post/reel", dependencies=[Depends(verify_api_key)])
async def post_reel(
    user_id: str = Form(...),
    caption: str = Form(""),
    video: UploadFile = File(None),
    video_url: str = Form(None),
    thumbnail: UploadFile = File(None),
):
    """Publica um Reel no Instagram."""
    cl = _require_client(user_id)
    tmp_video = None
    tmp_thumb = None

    try:
        if video:
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
            tmp.write(await video.read())
            tmp.close()
            tmp_video = tmp.name
        elif video_url:
            tmp_video = await _download_to_temp(video_url, ".mp4")
        else:
            raise HTTPException(status_code=400, detail="Envie um vídeo ou video_url.")

        if thumbnail:
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
            tmp.write(await thumbnail.read())
            tmp.close()
            tmp_thumb = tmp.name

        time.sleep(random.uniform(2, 5))
        extra = {}
        if tmp_thumb:
            extra["thumbnail"] = tmp_thumb

        media = cl.clip_upload(path=tmp_video, caption=caption, **extra)
        _update_last_used(user_id)

        logger.info(f"Reel publicado para user_id={user_id}, media_id={media.id}")
        return {
            "status": "published",
            "media_id": str(media.id),
            "media_type": "reel",
            "caption": caption,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao publicar Reel para {user_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        for p in [tmp_video, tmp_thumb]:
            if p and os.path.exists(p):
                os.unlink(p)


# ─── Publicação: Story ──────────────────────────────────────────────────────

@app.post("/instagram/post/story", dependencies=[Depends(verify_api_key)])
async def post_story(
    user_id: str = Form(...),
    image: UploadFile = File(None),
    image_url: str = Form(None),
):
    """Publica um Story de imagem no Instagram."""
    cl = _require_client(user_id)
    tmp_path = None

    try:
        if image:
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
            tmp.write(await image.read())
            tmp.close()
            tmp_path = tmp.name
        elif image_url:
            tmp_path = await _download_to_temp(image_url, ".jpg")
        else:
            raise HTTPException(status_code=400, detail="Envie uma imagem ou image_url.")

        time.sleep(random.uniform(1, 2))
        media = cl.photo_upload_to_story(path=tmp_path)
        _update_last_used(user_id)

        logger.info(f"Story publicado para user_id={user_id}, media_id={media.id}")
        return {
            "status": "published",
            "media_id": str(media.id),
            "media_type": "story",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao publicar Story para {user_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ─── Listar publicações recentes ────────────────────────────────────────────

@app.get("/instagram/media/{user_id}", dependencies=[Depends(verify_api_key)])
async def get_recent_media(user_id: str, limit: int = 12):
    """Retorna as últimas publicações da conta conectada."""
    cl = _require_client(user_id)
    try:
        medias = cl.user_medias(cl.user_id, amount=limit)
        return {
            "user_id": user_id,
            "count": len(medias),
            "media": [
                {
                    "id": str(m.id),
                    "type": m.media_type,
                    "caption": m.caption_text if m.caption_text else "",
                    "taken_at": m.taken_at.isoformat() if m.taken_at else None,
                    "like_count": m.like_count,
                    "comment_count": m.comment_count,
                    "thumbnail_url": str(m.thumbnail_url) if m.thumbnail_url else None,
                }
                for m in medias
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── Info da conta conectada ────────────────────────────────────────────────

@app.get("/instagram/account/{user_id}", dependencies=[Depends(verify_api_key)])
async def get_account_info(user_id: str):
    """Retorna informações básicas da conta Instagram conectada."""
    cl = _require_client(user_id)
    try:
        info = cl.account_info()
        return {
            "username": info.username,
            "full_name": info.full_name,
            "biography": info.biography,
            "follower_count": info.follower_count,
            "following_count": info.following_count,
            "media_count": info.media_count,
            "profile_pic_url": str(info.profile_pic_url) if info.profile_pic_url else None,
            "is_business": info.is_business,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── Listar todas as contas conectadas ──────────────────────────────────────

@app.get("/instagram/connections", dependencies=[Depends(verify_api_key)])
async def list_connections():
    """Lista todos os user_ids com conexão ativa (útil para admin)."""
    if redis_client:
        keys = redis_client.keys("ig:status:*")
        connections = []
        for key in keys:
            uid = key.replace("ig:status:", "")
            status = _load_status(uid)
            if status:
                connections.append({"user_id": uid, **status})
        return {"connections": connections}
    else:
        return {
            "connections": [
                {"user_id": uid, **status}
                for uid, status in _status_store.items()
            ]
        }


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("instagram_service:app", host="0.0.0.0", port=port, reload=False)

"""
=============================================================================
  INSTRUÇÕES DE INTEGRAÇÃO NO FRONTEND (Axis AI)
=============================================================================

1. CONECTAR UMA CONTA:

  const response = await fetch("https://SEU_SERVICO/instagram/connect", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": process.env.INSTAGRAM_API_KEY
    },
    body: JSON.stringify({
      user_id: "id-do-usuario-no-sistema",
      username: "instagram_username",
      password: "senha"
    })
  });

  const data = await response.json();
  // data.status === "connected" → ok
  // data.status === "challenge_required" → mostrar campo de código
  // data.status === "2fa_required" → mostrar campo de código do app autenticador

2. RESOLVER 2FA / CHECKPOINT:

  await fetch("https://SEU_SERVICO/instagram/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": "..." },
    body: JSON.stringify({ user_id: "...", code: "123456" })
  });

3. PUBLICAR NO FEED:

  const formData = new FormData();
  formData.append("user_id", "...");
  formData.append("caption", "Texto do post #hashtag");
  formData.append("image_url", "https://url-da-imagem.jpg"); // ou upload direto

  await fetch("https://SEU_SERVICO/instagram/post/feed", {
    method: "POST",
    headers: { "X-API-Key": "..." },
    body: formData
  });

4. PUBLICAR CARROSSEL:

  formData.append("image_urls", JSON.stringify(["url1.jpg", "url2.jpg", "url3.jpg"]));
  POST /instagram/post/carousel

5. PUBLICAR REEL:

  formData.append("video_url", "https://url-do-video.mp4");
  POST /instagram/post/reel

=============================================================================
  DEPLOY RÁPIDO NO RAILWAY:
  1. Crie um projeto no railway.app
  2. Adicione este arquivo como repositório
  3. Configure as variáveis de ambiente no painel
  4. Railway detecta FastAPI automaticamente
=============================================================================
"""
