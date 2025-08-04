from django.core.management.base import BaseCommand
from kpis.models import Directorate, PredefinedKPI

class Command(BaseCommand):
    help = 'Populates corporate directorate with financial KPIs'

    def handle(self, *args, **options):
        # Create or get corporate directorate
        corporate, created = Directorate.objects.get_or_create(
            name="Corporate",
            defaults={'description': "Corporate performance metrics"}
        )

        # KPI data with all required fields
        kpis_data = [
            {
                "name": "Operating profit",
                "unit_of_measurement": "Amount (Million)",
                "baseline": -9464.23,
                "monthly_target": 751.43,
                "logic": "higher",
                "aggregation_type": "sum"
            },
            {
                "name": "Revenue-to-Sales",
                "unit_of_measurement": "Percentage",
                "baseline": 87.0,
                "monthly_target": 94.0,
                "logic": "higher",
                "aggregation_type": "average"
            },
            {
                "name": "Receivables to Sales ratio",
                "unit_of_measurement": "Percentage",
                "baseline": 59.0,
                "monthly_target": 33.0,
                "logic": "lower",
                "aggregation_type": "average"
            },
            {
                "name": "System losses",
                "unit_of_measurement": "Percentage",
                "baseline": 27.7,
                "monthly_target": 22.0,
                "logic": "lower",
                "aggregation_type": "average"
            },
            {
                "name": "Amount in Inventory",
                "unit_of_measurement": "Amount (Million)",
                "baseline": 5119.38,
                "monthly_target": 2559.69,
                "logic": "lower",
                "aggregation_type": "sum"
            },
            {
                "name": "CWIP",
                "unit_of_measurement": "Number",
                "baseline": 2596.00,
                "monthly_target": 1217.00,
                "logic": "lower",
                "aggregation_type": "sum"
            },
            {
                "name": "Opex per kWH",
                "unit_of_measurement": "GHs/kWH",
                "baseline": 0.27,
                "monthly_target": 0.15,
                "logic": "lower",
                "aggregation_type": "average"
            },
            {
                "name": "SAIDI",
                "unit_of_measurement": "Duration",
                "baseline": 33.0,
                "monthly_target": 29.7,
                "logic": "lower",
                "aggregation_type": "average"
            },
            {
                "name": "SAIFI",
                "unit_of_measurement": "Hours",
                "baseline": 16.0,
                "monthly_target": 14.4,
                "logic": "lower",
                "aggregation_type": "average"
            },
            {
                "name": "Customer Satisfaction Index",
                "unit_of_measurement": "Percentage",
                "baseline": 62.2,
                "monthly_target": 65.0,
                "logic": "higher",
                "aggregation_type": "average"
            }
        ]

        # Create KPIs
        created_count = 0
        for kpi_data in kpis_data:
            _, created = PredefinedKPI.objects.get_or_create(
                directorate=corporate,
                name=kpi_data['name'],
                defaults=kpi_data
            )
            if created:
                created_count += 1

        self.stdout.write(
            self.style.SUCCESS(f'Successfully created {created_count} KPIs for Corporate directorate')
        )