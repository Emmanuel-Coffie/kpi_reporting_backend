from django.core.management.base import BaseCommand
from django.db import transaction
from kpis.models import PredefinedKPI, MonthlyTarget

class Command(BaseCommand):
    help = 'Create monthly targets for all KPIs'

    @transaction.atomic
    def handle(self, *args, **options):
        # Get all predefined KPIs
        kpis = PredefinedKPI.objects.all()
        
        created_count = 0
        
        for kpi in kpis:
            # Create targets for each month (January to December)
            for month in range(1, 13):
                # Check if target already exists
                if not MonthlyTarget.objects.filter(
                    predefined_kpi=kpi,
                    year=2025,
                    month=month
                ).exists():
                    MonthlyTarget.objects.create(
                        predefined_kpi=kpi,
                        year=2025,
                        month=month,
                        target_value=kpi.monthly_target
                    )
                    created_count += 1
        
        self.stdout.write(self.style.SUCCESS(f'Created {created_count} monthly targets'))