from django.contrib import admin
from .models import (PredefinedKPI, KPIActual, Directorate, 
                    KPIYear, MonthlyTarget, ReportingPeriod, KPIDocument)

@admin.register(ReportingPeriod)
class ReportingPeriodAdmin(admin.ModelAdmin):
    list_display = ('year', 'month', 'is_open', 'open_date', 'close_date')
    list_editable = ('is_open',)
    ordering = ('-year', '-month')

@admin.register(KPIYear)
class KPIYearAdmin(admin.ModelAdmin):
    list_display = ('year', 'is_current')
    actions = ['set_as_current_year']
    
    def set_as_current_year(self, request, queryset):
        if queryset.count() != 1:
            self.message_user(request, "Please select exactly one year", level='error')
            return
        
        KPIYear.objects.filter(is_current=True).update(is_current=False)
        queryset.update(is_current=True)
        self.message_user(request, "Current year updated")

@admin.register(PredefinedKPI)
class PredefinedKPIAdmin(admin.ModelAdmin):
    list_display = ('name', 'directorate', 'kpi_year', 'unit_of_measurement')
    list_filter = ('kpi_year', 'directorate')

@admin.register(MonthlyTarget)
class MonthlyTargetAdmin(admin.ModelAdmin):
    list_display = ('predefined_kpi', 'year', 'month', 'target_value')
    list_filter = ('year', 'month', 'predefined_kpi__directorate')

@admin.register(Directorate)
class DirectorateAdmin(admin.ModelAdmin):
    list_display = ('name', 'user')
    search_fields = ('name',)

@admin.register(KPIActual)
class KPIActualAdmin(admin.ModelAdmin):
    list_display = ('predefined_kpi', 'directorate', 'year', 'month', 
                   'actual_value', 'is_submitted')
    list_filter = ('year', 'month', 'directorate', 'is_submitted')
    search_fields = ('predefined_kpi__name',)

@admin.register(KPIDocument)
class KPIDocumentAdmin(admin.ModelAdmin):
    list_display = ('kpi_actual', 'file_name', 'file_type', 'uploaded_at', 'uploaded_by')
    list_filter = ('file_type', 'uploaded_at')
    search_fields = ('file_name', 'kpi_actual__predefined_kpi__name')
    readonly_fields = ('file_name', 'file_type', 'uploaded_at', 'uploaded_by')
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('kpi_actual', 'uploaded_by')