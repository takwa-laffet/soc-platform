from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Global limiter reused by blueprints and app routes.
limiter = Limiter(
	key_func=get_remote_address,
	default_limits=["10000 per minute"],
	storage_uri="memory://",
)
