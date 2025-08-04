import pandas as pd
from django.core.management.base import BaseCommand
from kpis.models import Directorate, Initiative, Activity
from django.db.models import Q

class Command(BaseCommand):
    help = 'Import activities from Excel with detailed error reporting'

    def handle(self, *args, **options):
        df = pd.read_excel('Initiative-activities mapping.xlsx', sheet_name='2025 Comms Workplan')
        
        # Initialize counters
        total_activities = 0
        created_count = 0
        skipped_count = 0
        skipped_details = []

        # Clean data - more thorough cleaning
        df['Directorate'] = df['Directorate'].str.strip().str.replace(r'\s+', ' ', regex=True)
        df['INITIATIVE'] = df['INITIATIVE'].str.strip().str.replace(r'\s+', ' ', regex=True) if 'INITIATIVE' in df.columns else None
        df['ACTIVITY'] = df['ACTIVITY'].str.strip().str.replace(r'\s+', ' ', regex=True)

        for index, row in df.iterrows():
            # Skip empty rows (more comprehensive check)
            if pd.isna(row['Directorate']) or pd.isna(row['ACTIVITY']) or row['ACTIVITY'] == '':
                skipped_count += 1
                skipped_details.append({
                    'row': index + 2,  # +1 for header, +1 for 0-based index
                    'activity': row.get('ACTIVITY', ''),
                    'reason': 'Empty directorate or activity'
                })
                continue

            total_activities += 1
            directorate_name = row['Directorate']
            initiative_name = row['INITIATIVE'] if 'INITIATIVE' in df.columns and not pd.isna(row['INITIATIVE']) else None
            activity_name = row['ACTIVITY']

            # Find Directorate (more flexible matching)
            directorate = Directorate.objects.filter(
                Q(name__iexact=directorate_name) |
                Q(name__iexact=directorate_name.replace('&', 'and'))  # Handle & vs and variations
            ).first()
            
            if not directorate:
                skipped_count += 1
                skipped_details.append({
                    'row': index + 2,
                    'directorate': directorate_name,
                    'initiative': initiative_name,
                    'activity': activity_name,
                    'reason': f"Directorate '{directorate_name}' not found"
                })
                self.stdout.write(self.style.ERROR(
                    f"⚠ Row {index + 2}: Directorate '{directorate_name}' not found. "
                    f"Activity: '{activity_name}'"
                ))
                continue

            # Find Initiative if specified
            initiative = None
            if initiative_name:
                # More flexible initiative matching
                initiative = Initiative.objects.filter(
                    Q(title__iexact=initiative_name) |
                    Q(title__iexact=initiative_name.replace('&', 'and')) |
                    Q(title__icontains=initiative_name),  # Partial match
                    directorate=directorate
                ).first()
                
                if not initiative:
                    skipped_count += 1
                    skipped_details.append({
                        'row': index + 2,
                        'directorate': directorate.name,
                        'initiative': initiative_name,
                        'activity': activity_name,
                        'reason': f"Initiative '{initiative_name}' not found under directorate"
                    })
                    self.stdout.write(self.style.ERROR(
                        f"⚠ Row {index + 2}: Initiative '{initiative_name}' not found under "
                        f"'{directorate.name}'. Activity: '{activity_name}'\n"
                        f"Existing initiatives for this directorate: {list(Initiative.objects.filter(directorate=directorate).values_list('title', flat=True))}"
                    ))
                    continue

            # Create Activity (with duplicate prevention)
            try:
                activity, created = Activity.objects.get_or_create(
                    initiative=initiative,
                    name=activity_name,
                    defaults={'description': ''}
                )

                if created:
                    created_count += 1
                    self.stdout.write(self.style.SUCCESS(
                        f"✓ Row {index + 2}: Created activity: '{activity_name}' "
                        f"under {f'initiative: {initiative.title}' if initiative else f'directorate: {directorate.name}'}"
                    ))
                else:
                    self.stdout.write(self.style.WARNING(
                        f"☑ Row {index + 2}: Activity already exists: '{activity_name}'"
                    ))
            except Exception as e:
                skipped_count += 1
                skipped_details.append({
                    'row': index + 2,
                    'directorate': directorate.name,
                    'initiative': initiative.title if initiative else None,
                    'activity': activity_name,
                    'reason': f"Creation error: {str(e)}"
                })
                self.stdout.write(self.style.ERROR(
                    f"⚠ Row {index + 2}: Error creating activity '{activity_name}': {str(e)}"
                ))

        # Final report
        self.stdout.write(self.style.SUCCESS(
            f"\nImport completed!\n"
            f"Total activities processed: {total_activities}\n"
            f"Created: {created_count}\n"
            f"Skipped: {skipped_count}\n"
        ))
        
        if skipped_details:
            self.stdout.write(self.style.WARNING("\nSkipped activities details:"))
            for detail in skipped_details:
                self.stdout.write(self.style.WARNING(
                    f"Row {detail['row']}: {detail.get('activity', '')} - {detail['reason']}"
                ))
            
            # Optionally save skipped details to a file
            pd.DataFrame(skipped_details).to_csv('skipped_activities_report.csv', index=False)
            self.stdout.write(self.style.WARNING(
                "\nDetailed skipped activities report saved to 'skipped_activities_report.csv'"
            ))