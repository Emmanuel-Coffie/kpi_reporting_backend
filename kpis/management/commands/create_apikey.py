from django.core.management.base import BaseCommand
from kpis.models import APIKey
from django.utils import timezone
from datetime import timedelta

class Command(BaseCommand):
    help = 'Creates a new API key for external systems'

    def add_arguments(self, parser):
        parser.add_argument('name', type=str, help='Name/identifier for the key')
        parser.add_argument('--expiry', type=str, help='Expiry date (YYYY-MM-DD)')
        parser.add_argument('--days', type=int, help='Number of days until expiry')
        parser.add_argument('--description', type=str, help='Description of key usage')

    def handle(self, *args, **options):
        expiry_date = None
        if options['expiry']:
            expiry_date = timezone.datetime.strptime(options['expiry'], '%Y-%m-%d').date()
        elif options['days']:
            expiry_date = (timezone.now() + timedelta(days=options['days'])).date()
        
        key = APIKey.objects.create(
            name=options['name'],
            expiry_date=expiry_date,
            description=options['description'] or ''
        )
        
        self.stdout.write(self.style.SUCCESS(f'API Key created for {key.name}'))
        self.stdout.write(f'Key: {key.key}')
        self.stdout.write(f'Expires: {key.expiry_date or "Never"}')
        self.stdout.write(self.style.WARNING('Store this securely - it will not be shown again!'))