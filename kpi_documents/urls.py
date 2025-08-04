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
    DirectorateKPIsView,AdminReportingPeriodDetailView,AdminKPISubmissionView,KPIDocumentUploadView
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
    # Auth endpoints
    path('auth/login/', DirectorateLoginView.as_view(), name='directorate_login'),
    path('auth/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/me/', current_user_info, name='current_user'),
]