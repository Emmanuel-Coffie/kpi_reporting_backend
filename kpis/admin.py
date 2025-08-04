from django.contrib import admin
from .models import (PredefinedKPI, KPIActual, Directorate, 
                    KPIYear, MonthlyTarget, ReportingPeriod, KPIDocument, ActivityReport,Activity, Initiative)

from django.contrib import admin

from kpis.models import APIKey

@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_active', 'created_at', 'last_used', 'expiry_date', 'is_expired')
    list_filter = ('is_active',)
    search_fields = ('name', 'key', 'description')
    readonly_fields = ('key', 'created_at', 'last_used', 'is_expired')
    fieldsets = (
        (None, {
            'fields': ('name', 'key', 'is_active', 'description')
        }),
        ('Dates', {
            'fields': ('created_at', 'last_used', 'expiry_date'),
            'classes': ('collapse',)
        })
    )
    actions = ['deactivate_keys', 'activate_keys']
    
    def get_readonly_fields(self, request, obj=None):
        if obj:  # Editing an existing object
            return self.readonly_fields + ('key',)
        return self.readonly_fields
    
    def is_expired(self, obj):
        return obj.is_expired
    is_expired.boolean = True
    
    @admin.action(description='Deactivate selected keys')
    def deactivate_keys(self, request, queryset):
        queryset.update(is_active=False)
    
    @admin.action(description='Activate selected keys')
    def activate_keys(self, request, queryset):
        queryset.update(is_active=True)

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
    list_display = ('name', 'user_count')
    search_fields = ('name',)
    filter_horizontal = ('users',)
    
    def user_count(self, obj):
        return obj.users.count()
    user_count.short_description = 'Users'

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
    

@admin.register(Initiative)
class InitiativeAdmin(admin.ModelAdmin):
    list_display = ('title', 'directorate', 'kpi_year', 'start_date', 'end_date')
    list_filter = ('directorate', 'kpi_year')
    search_fields = ('title', 'description')
    filter_horizontal = ('linked_kpis',)
    date_hierarchy = 'start_date'

@admin.register(Activity)
class ActivityAdmin(admin.ModelAdmin):
    list_display = ('name', 'initiative', 'directorate')
    list_filter = ('initiative__directorate',)
    search_fields = ('name', 'description')
    
    def directorate(self, obj):
        return obj.initiative.directorate
    directorate.short_description = 'Directorate'
    directorate.admin_order_field = 'initiative__directorate'

@admin.register(ActivityReport)
class ActivityReportAdmin(admin.ModelAdmin):
    list_display = ('activity', 'year', 'month', 'status', 'is_submitted', 'submitted_at')
    list_filter = ('year', 'month', 'status', 'is_submitted', 'activity__initiative__directorate')
    search_fields = ('activity__name', 'challenges')
    readonly_fields = ('submitted_at', 'last_updated')
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'activity', 
            'activity__initiative', 
            'submitted_by'
        )
