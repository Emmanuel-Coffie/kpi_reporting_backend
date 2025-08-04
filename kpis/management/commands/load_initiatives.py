# management/commands/load_initiatives.py
from django.core.management.base import BaseCommand
from kpis.models import Directorate, PredefinedKPI, Initiative, KPIYear
import pandas as pd
from django.db import transaction
from difflib import get_close_matches
import unicodedata

class Command(BaseCommand):
    help = 'Loads initiatives from Excel and maps them to KPIs and directorates'

    def handle(self, *args, **options):
        # Path to your Excel file (adjust as needed)
        excel_path = 'Initiatives-KPIs mapping.xlsx'
        
        try:
            # Read the Excel file
            df = pd.read_excel(excel_path, sheet_name='Directorates_KPIs')
            
            # Get or create the current KPI year
            current_year = 2025  # Adjust this to your current year
            kpi_year, created = KPIYear.objects.get_or_create(
                year=current_year,
                defaults={'is_current': True}
            )
            
            # Pre-load all directorates and KPIs for performance
            all_directorates = list(Directorate.objects.all())
            all_kpis = list(PredefinedKPI.objects.filter(kpi_year=kpi_year))
            
            with transaction.atomic():
                # Process each row in the Excel file
                for index, row in df.iterrows():
                    directorate_name = self.normalize_string(row['Directorate'])
                    initiative_title = self.normalize_string(row['Initiative'])
                    kpi_name = self.normalize_string(row['Directorate KPI'])
                    
                    try:
                        # Get the directorate with fuzzy matching
                        directorate = self.find_directorate(directorate_name, all_directorates)
                        if not directorate:
                            raise Directorate.DoesNotExist(f"Directorate '{directorate_name}' not found")
                        
                        # Create or get the initiative
                        initiative, created = Initiative.objects.get_or_create(
                            directorate=directorate,
                            title=initiative_title,
                            kpi_year=kpi_year,
                            defaults={
                                'description': f"Initiative for {directorate.name}",
                                'start_date': f"{current_year}-01-01",
                                'end_date': f"{current_year}-12-31"
                            }
                        )
                        
                        # Get the KPI with fuzzy matching
                        kpi = self.find_kpi(directorate, kpi_name, kpi_year, all_kpis)
                        if not kpi:
                            raise PredefinedKPI.DoesNotExist(f"KPI '{kpi_name}' not found for directorate '{directorate.name}'")
                        
                        # Link KPI to initiative if not already linked
                        if not initiative.linked_kpis.filter(id=kpi.id).exists():
                            initiative.linked_kpis.add(kpi)
                            self.stdout.write(self.style.SUCCESS(
                                f"Linked KPI '{kpi.name}' to initiative '{initiative.title}' for {directorate.name}"
                            ))
                        else:
                            self.stdout.write(self.style.WARNING(
                                f"KPI '{kpi.name}' already linked to initiative '{initiative.title}' for {directorate.name}"
                            ))
                            
                    except Directorate.DoesNotExist as e:
                        self.stdout.write(self.style.ERROR(
                            f"Directorate '{directorate_name}' not found. Similar directorates: {self.get_similar_directorates(directorate_name, all_directorates)}"
                        ))
                    except PredefinedKPI.DoesNotExist as e:
                        self.stdout.write(self.style.ERROR(
                            f"KPI '{kpi_name}' not found for directorate '{directorate.name}'. Similar KPIs: {self.get_similar_kpis(directorate, kpi_name, all_kpis)}"
                        ))
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(
                            f"Error processing row {index}: {str(e)}"
                        ))
                        if hasattr(e, '__traceback__'):
                            import traceback
                            self.stdout.write(self.style.ERROR(
                                traceback.format_exc()
                            ))
                
                self.stdout.write(self.style.SUCCESS("Finished loading initiatives and mapping KPIs"))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error loading Excel file: {str(e)}"))
            if hasattr(e, '__traceback__'):
                import traceback
                self.stdout.write(self.style.ERROR(
                    traceback.format_exc()
                ))

    def normalize_string(self, s):
        """Normalize strings for comparison by removing extra spaces and making case insensitive"""
        if pd.isna(s):
            return ""
        return ' '.join(str(s).strip().split()).lower()

    def find_directorate(self, name, all_directorates):
        """Find directorate with fuzzy matching"""
        normalized_name = self.normalize_string(name)
        for directorate in all_directorates:
            if self.normalize_string(directorate.name) == normalized_name:
                return directorate
        return None

    def find_kpi(self, directorate, name, kpi_year, all_kpis):
        """Find KPI with fuzzy matching"""
        normalized_name = self.normalize_string(name)
        for kpi in all_kpis:
            if (kpi.directorate == directorate and 
                self.normalize_string(kpi.name) == normalized_name and
                kpi.kpi_year == kpi_year):
                return kpi
        return None

    def get_similar_directorates(self, name, all_directorates, limit=3):
        """Get similar directorate names for error reporting"""
        names = [d.name for d in all_directorates]
        matches = get_close_matches(name.lower(), [n.lower() for n in names], n=limit, cutoff=0.6)
        return matches or "none found"

    def get_similar_kpis(self, directorate, name, all_kpis, limit=3):
        """Get similar KPI names for error reporting"""
        kpi_names = [k.name for k in all_kpis if k.directorate == directorate]
        matches = get_close_matches(name.lower(), [n.lower() for n in kpi_names], n=limit, cutoff=0.6)
        return matches or "none found"