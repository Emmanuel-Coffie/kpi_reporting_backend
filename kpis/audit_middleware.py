import logging
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from .models import AuditLog
import json

logger = logging.getLogger('audit')

class AuditMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            try:
                # Skip binary file uploads
                content_type = request.content_type
                if content_type and 'multipart/form-data' in content_type:
                    request.audit_data = {
                        'path': request.path,
                        'method': request.method,
                        'data': 'FILE_UPLOAD'
                    }
                else:
                    # Handle JSON or form data
                    if request.body:
                        try:
                            body_data = json.loads(request.body.decode('utf-8'))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            body_data = 'BINARY_DATA'
                    else:
                        body_data = None
                    
                    request.audit_data = {
                        'path': request.path,
                        'method': request.method,
                        'data': request.POST.dict() or body_data
                    }
            except Exception as e:
                logger.error(f"Error processing audit data: {str(e)}")
                request.audit_data = {
                    'path': request.path,
                    'method': request.method,
                    'data': 'ERROR_PROCESSING'
                }
        return None

    def process_response(self, request, response):
        try:
            user = request.user if request.user.is_authenticated else None
            action = self._determine_action(request)
            
            if action:
                log_data = {
                    'user': user,
                    'action': action,
                    'ip_address': self._get_client_ip(request),
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                    'status': 'SUCCESS' if response.status_code < 400 else 'FAILED',
                    'details': {
                        'path': request.path,
                        'method': request.method,
                        'status_code': response.status_code,
                    },
                    # Make session_key optional
                    'session_key': request.session.session_key if hasattr(request, 'session') else None
                }
                
                # Only include response content if it exists and is text
                if response.content and isinstance(response.content, (str, bytes)):
                    log_data['details']['response'] = str(response.content)[:500]
                
                AuditLog.objects.create(**log_data)
                
        except Exception as e:
            logger.error("Failed to create audit log", exc_info=True)
        
        return response

    def _determine_action(self, request):
        if request.path.endswith('/login/'):
            return 'LOGIN'
        elif request.path.endswith('/logout/'):
            return 'LOGOUT'
        elif request.method == 'POST':
            return 'CREATE'
        elif request.method == 'PUT' or request.method == 'PATCH':
            return 'UPDATE'
        elif request.method == 'DELETE':
            return 'DELETE'
        return None

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip