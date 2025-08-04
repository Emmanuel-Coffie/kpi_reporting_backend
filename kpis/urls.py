from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    CustomTokenObtainPairView,
    DirectorateLoginView,
    current_user_info,
    KPIDataCaptureView,
    PreviousReportsView,
    CurrentReportingPeriodView,
    AdminReportingPeriodView,
    AdminMonthlyTargetView,
    AdminDirectorateView,
    AdminKPITargetView,
    DirectorateKPIsView,AdminReportingPeriodDetailView,AdminKPISubmissionView,KPIDocumentUploadView,
    ChangePasswordView,ExternalKPIDataView,AuditLogListView, CommunicationLogListView, 
    certificate_revocation_list, revoke_certificate,TwoFactorSendCodeView, TwoFactorVerifyView,ActivityReportView,
    InitiativeListView, InitiativeDetailView, InitiativeDashboardView,DirectorateInitiativesView,InitiativeActivitiesView,
    ActivityReportDetailView, ActivityReportCreateView,AdminActivitySubmissionView,DirectorateReportView
)

urlpatterns = [
    # User endpoints
    path('reporting/current/', CurrentReportingPeriodView.as_view(), name='current-reporting-period'),
    path('reporting/data/', KPIDataCaptureView.as_view(), name='kpi-data-capture'),
    path('reporting/previous/', PreviousReportsView.as_view(), name='previous-reports'),
    path('admin/set-targets/', AdminKPITargetView.as_view(), name='admin-set-targets'),
    path('directorates/<int:pk>/kpis/', DirectorateKPIsView.as_view(), name='directorate-kpis'),
    path('admin/reporting-periods/<int:pk>/', AdminReportingPeriodDetailView.as_view(), name='admin-reporting-period-detail'),
    path('directorates/<int:pk>/kpis/', DirectorateKPIsView.as_view(), name='directorate-kpis'),
    path('kpi-actuals/<int:kpi_actual_id>/documents/', KPIDocumentUploadView.as_view(), name='kpi-document-upload'),
    
    # Admin endpoints
    path('admin/reporting-periods/', AdminReportingPeriodView.as_view(), name='admin-reporting-periods'),
    path('admin/monthly-targets/', AdminMonthlyTargetView.as_view(), name='admin-monthly-targets'),
    path('admin/directorates/', AdminDirectorateView.as_view(), name='admin-directorates'),
       path('admin/kpi-submissions/', AdminKPISubmissionView.as_view(), name='admin-kpi-submissions'),
       path('admin/activity-submissions/', AdminActivitySubmissionView.as_view(), name='admin-activity-submissions'),
       path('admin/directorate-reports/', DirectorateReportView.as_view(), name='directorate-reports'),
    # Auth endpoints
    path('auth/login/', DirectorateLoginView.as_view(), name='directorate_login'),
    path('auth/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/me/', current_user_info, name='current_user'),
    path('auth/change-password/', ChangePasswordView.as_view(), name='change_password'),

    path('external/kpi-data/', ExternalKPIDataView.as_view(), name='external-kpi-data'),
     # Audit and security URLs
    path('audit/logs/', AuditLogListView.as_view(), name='audit-logs'),
    path('audit/communications/', CommunicationLogListView.as_view(), name='communication-logs'),
    path('security/crl/', certificate_revocation_list, name='certificate-revocation-list'),
    path('security/revoke/', revoke_certificate, name='revoke-certificate'),
    # Two-factor authentication
    path('auth/2fa/send-code/', TwoFactorSendCodeView.as_view(), name='2fa-send-code'),
    path('auth/2fa/verify/', TwoFactorVerifyView.as_view(), name='2fa-verify'),
     path('initiatives/', InitiativeListView.as_view(), name='initiative-list'),
    path('initiatives/<int:pk>/', InitiativeDetailView.as_view(), name='initiative-detail'),
    path('activity-reports/', ActivityReportView.as_view(), name='activity-reports'),
    path('admin/initiative-dashboard/', InitiativeDashboardView.as_view(), name='initiative-dashboard'),
    path('directorates/<int:directorate_id>/initiatives/', DirectorateInitiativesView.as_view(), name='directorate-initiatives'),
path('initiatives/<int:initiative_id>/activities/', InitiativeActivitiesView.as_view(), name='initiative-activities'),
path('activity-reports/<int:report_id>/', ActivityReportDetailView.as_view(), name='activity-report-detail'),
path('activities/<int:activity_id>/reports/', ActivityReportCreateView.as_view(), name='activity-report-create'),
]