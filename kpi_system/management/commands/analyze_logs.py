from django.core.management.base import BaseCommand
from django.utils import timezone
from kpis.models import AuditLog
import pandas as pd
from sklearn.ensemble import IsolationForest

class Command(BaseCommand):
    help = 'Run anomaly detection on audit logs'
    
    def handle(self, *args, **options):
        # Get recent logs
        logs = AuditLog.objects.filter(
            timestamp__gte=timezone.now() - timezone.timedelta(days=1)
        ).values('action', 'status', 'user_id', 'ip_address')
        
        # Convert to DataFrame for analysis
        df = pd.DataFrame.from_records(logs)
        
        # Simple anomaly detection
        model = IsolationForest(contamination=0.01)
        df['anomaly'] = model.fit_predict(df[['action', 'status']])
        
        # Log or alert on anomalies
        anomalies = df[df['anomaly'] == -1]
        if not anomalies.empty:
            logger.warning(f"Detected anomalous activities: {anomalies.to_dict('records')}")