import logging
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.db.models import Q, Count
from kpis.models import AuditLog, CommunicationLog, RevokedCertificate

logger = logging.getLogger(__name__)

class SecurityMonitor:
    def check_suspicious_activity(self):
        """Check for suspicious patterns in logs"""
        time_threshold = datetime.now() - timedelta(minutes=15)
        
        # Multiple failed logins from same IP
        failed_logins = AuditLog.objects.filter(
            action='LOGIN',
            status='FAILED',
            timestamp__gte=time_threshold
        ).values('ip_address').annotate(count=Count('ip_address')).filter(count__gte=5)
        
        if failed_logins.exists():
            logger.warning(
                f"Possible brute force attack detected from IPs: {list(failed_logins)}"
            )
            self.trigger_alert("Brute force attempt", failed_logins)
        
        # Check for unusual admin actions
        sensitive_actions = AuditLog.objects.filter(
            Q(action='DELETE') | Q(action='PASSWORD_CHANGE'),
            timestamp__gte=time_threshold,
            user__is_superuser=True
        )
        
        if sensitive_actions.exists():
            logger.warning(
                f"Sensitive admin actions detected: {sensitive_actions.count()}"
            )
    
    def trigger_alert(self, alert_type, details):
        """Trigger appropriate alert response"""
        # Implement your alerting mechanism (email, SMS, Slack, etc.)
        pass

    def check_unusual_activity(self):
        """Check for unusual patterns in logs"""
        time_threshold = datetime.now() - timedelta(minutes=15)
        
        # Multiple actions from same IP in short time
        rapid_actions = AuditLog.objects.filter(
            timestamp__gte=time_threshold
        ).values('ip_address').annotate(count=Count('ip_address')).filter(count__gte=20)
        
        if rapid_actions.exists():
            logger.warning(f"Possible automated activity from IPs: {list(rapid_actions)}")
            self.trigger_alert("Automated activity detected", rapid_actions)
        
        # Check for access to sensitive endpoints
        sensitive_access = AuditLog.objects.filter(
            Q(path__contains='/admin/') | Q(path__contains='/api/keys/'),
            user__is_superuser=False,
            timestamp__gte=time_threshold
        )
        
        if sensitive_access.exists():
            logger.warning(f"Unauthorized access to sensitive endpoints: {sensitive_access.count()}")
            
    def check_certificate_activity(self):
        """Check certificate-related activity"""
        time_threshold = datetime.now() - timedelta(hours=1)
        
        # Multiple certificate revocations
        revocations = RevokedCertificate.objects.filter(
            revocation_date__gte=time_threshold
        ).count()
        
        if revocations > 5:
            logger.warning(f"High number of certificate revocations: {revocations}")

class Command(BaseCommand):
    help = 'Run security monitoring checks'
    
    def handle(self, *args, **options):
        monitor = SecurityMonitor()
        monitor.check_suspicious_activity()
        self.stdout.write(self.style.SUCCESS('Completed security monitoring checks'))