from rest_framework import generics, status
from django.core.exceptions import PermissionDenied
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from kpis.models import APIKey
import os
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from django.utils import timezone
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.contrib.auth import authenticate
from django.conf import settings
from django.db import IntegrityError
import logging
logger = logging.getLogger(__name__)
from datetime import datetime
from .models import (PredefinedKPI, KPIActual, Directorate,
                    ReportingPeriod, MonthlyTarget,AuditLog, KPIDocument,
                    RevokedCertificate, CommunicationLog, APIKey, TwoFactorAuth,Initiative, ActivityReport, Activity)
from .serializers import (KPIActualSerializer, PredefinedKPISerializer,
                         DirectorateSerializer, ReportingPeriodSerializer,MonthlyTargetSerializer,CustomTokenObtainPairSerializer,
                         KPIDocumentSerializer,ExternalKPISerializer,
                         RevokedCertificateSerializer, CommunicationLogSerializer, AuditLogSerializer,ActivityReportSerializer,
                         ActivitySerializer, InitiativeSerializer, TwoFactorVerifySerializer)
from .permissions import IsAdminOrStaff
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import update_session_auth_hash
from rest_framework.views import APIView
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from rest_framework.throttling import AnonRateThrottle
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime
from cryptography.hazmat.primitives import hashes
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django_otp.plugins.otp_totp.models import TOTPDevice


class TwoFactorSendCodeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # This will be called after initial login with temp tokens
        user = request.user
        try:
            two_factor = TwoFactorAuth.objects.get(user=user)
        except TwoFactorAuth.DoesNotExist:
            two_factor = TwoFactorAuth.objects.create(user=user, email=user.email)

        # Generate and send code
        code = two_factor.generate_code()

        # Send email with code
        subject = 'Your 2FA Verification Code'
        html_message = render_to_string('2fa_email.html', {
            'code': code,
            'user': user
        })
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject,
            plain_message,
            'noreply@yourdomain.com',
            [user.email],
            html_message=html_message,
            fail_silently=False
        )

        return Response({'status': 'code_sent'})

class TwoFactorVerifyView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = TwoFactorVerifySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        temp_access = data['temp_access']
        temp_refresh = data['temp_refresh']

        # Verify temp tokens first
        try:
            # This is a simplified version - in production, you'd properly verify the temp tokens
            user_id = AccessToken(temp_access).payload['user_id']
            user = User.objects.get(id=user_id)
            
            two_factor = TwoFactorAuth.objects.get(user=user)
            if not two_factor.is_code_valid(data['code']):
                return Response({'error': 'Invalid or expired code'}, status=status.HTTP_400_BAD_REQUEST)

            # If code is valid, generate final tokens
            refresh = RefreshToken.for_user(user)
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_staff': user.is_staff,
                    'is_superuser': user.is_superuser,
                }
            })

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class AuditLogListView(generics.ListAPIView):
    permission_classes = [IsAdminOrStaff]
    serializer_class = AuditLogSerializer
    queryset = AuditLog.objects.all().order_by('-timestamp')
    filterset_fields = ['user', 'action', 'status', 'timestamp']
    search_fields = ['user__username', 'action', 'details']

class CommunicationLogListView(generics.ListAPIView):
    permission_classes = [IsAdminOrStaff]
    serializer_class = CommunicationLogSerializer
    queryset = CommunicationLog.objects.all().order_by('-timestamp')
    filterset_fields = ['user', 'type', 'direction', 'status']
    search_fields = ['user__username', 'recipient', 'subject', 'content']

@api_view(['GET'])
@permission_classes([AllowAny])
def certificate_revocation_list(request):
  
    revoked_certs = RevokedCertificate.objects.all()
    
    
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.last_update(datetime.datetime.now())
    builder = builder.next_update(datetime.datetime.now() + datetime.timedelta(days=1))
    
    for cert in revoked_certs:
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            int(cert.serial_number, 16)
        ).revocation_date(
            cert.revocation_date
        ).build(default_backend())
        builder = builder.add_revoked_certificate(revoked_cert)
    

    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    crl = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    
    return HttpResponse(
        crl.public_bytes(serialization.Encoding.PEM),
        content_type='application/x-pem-file'
    )



@api_view(['POST'])
@permission_classes([IsAdminOrStaff])
def revoke_certificate(request):
    """
    Revokes a certificate
    """
    serializer = RevokedCertificateSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(revoked_by=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(ensure_csrf_cookie, name='dispatch')
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        
        if not old_password or not new_password:
            return Response(
                {"error": "Both old and new password are required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not check_password(old_password, user.password):
            return Response(
                {"error": "Old password is incorrect"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if old_password == new_password:
            return Response(
                {"error": "New password must be different from old password"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.set_password(new_password)
        user.save()
        
        # Update session to prevent logout
        update_session_auth_hash(request, user)
        
        return Response(
            {"success": "Password updated successfully"},
            status=status.HTTP_200_OK
        )

class DirectorateKPIsView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk):
        try:
            directorate = Directorate.objects.get(pk=pk)
            kpis = PredefinedKPI.objects.filter(directorate=directorate)
            serializer = PredefinedKPISerializer(kpis, many=True)
            return Response(serializer.data)
        except Directorate.DoesNotExist:
            return Response(
                {"error": "Directorate not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        


class AdminDirectorateView(APIView):
    """
    Allows superusers or staff to manage directorates.
    """
    permission_classes = [IsAdminOrStaff]
    
    def get(self, request, pk=None):
        if pk:
            try:
                directorate = Directorate.objects.get(pk=pk)
                serializer = DirectorateSerializer(directorate)
                return Response(serializer.data)
            except Directorate.DoesNotExist:
                return Response({'error': 'Directorate not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            directorates = Directorate.objects.all()
            serializer = DirectorateSerializer(directorates, many=True)
            return Response(serializer.data)

    def post(self, request):
        serializer = DirectorateSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        try:
            directorate = Directorate.objects.get(pk=pk)
        except Directorate.DoesNotExist:
            return Response({'error': 'Directorate not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = DirectorateSerializer(directorate, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        try:
            directorate = Directorate.objects.get(pk=pk)
            directorate.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Directorate.DoesNotExist:
            return Response({'error': 'Directorate not found'}, status=status.HTTP_404_NOT_FOUND)

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

class DirectorateLoginView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)
        if not user:
            return Response({'error': 'Invalid credentials'}, status=401)

        # Check if user has 2FA enabled
        has_2fa = TOTPDevice.objects.filter(user=user, confirmed=True).exists()
        
        if has_2fa:
            # Generate temporary tokens for 2FA verification
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            
            # Store temporary tokens in response (not in local storage yet)
            return Response({
                'requires_2fa': True,
                'temp_access': access_token,
                'temp_refresh': refresh_token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_staff': user.is_staff,
                    'is_superuser': user.is_superuser,
                }
            })
        else:
            # Normal login flow - generate final tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            
            response_data = {
                'access': access_token,
                'refresh': refresh_token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_staff': user.is_staff,
                    'is_superuser': user.is_superuser,
                }
            }

            # Add directorates info
            directorates = user.directorates.all()
            if directorates.exists():
                response_data['user']['directorates'] = DirectorateSerializer(directorates, many=True).data

            response = Response(response_data)
            
            # Set secure cookies if in production
            if not settings.DEBUG:
                response.set_cookie(
                    'access_token',
                    access_token,
                    httponly=True,
                    secure=True,
                    samesite='Strict'
                )
                response.set_cookie(
                    'refresh_token',
                    refresh_token,
                    httponly=True,
                    secure=True,
                    samesite='Strict'
                )
            
            return response

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user_info(request):
    directorates = request.user.directorates.all()
    directorates_data = DirectorateSerializer(directorates, many=True).data if directorates.exists() else None
    
    return Response({
        'user': {
            'id': request.user.id,
            'username': request.user.username,
            'email': request.user.email,
            'is_staff': request.user.is_staff,
            'is_superuser': request.user.is_superuser,
        },
        'directorates': directorates_data
    })

class CurrentReportingPeriodView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # First find the active period
        current_period = ReportingPeriod.objects.filter(
            is_active=True
        ).first()
        
        if not current_period:
            return Response(
                {"error": "No active reporting period"},
                status=status.HTTP_404_NOT_FOUND
            )
            
        # Then check if it's within the open window
        today = timezone.now().date()
        if not (current_period.open_date <= today <= current_period.close_date):
            return Response(
                {"error": "Active reporting period window is closed"},
                status=status.HTTP_403_FORBIDDEN
            )
            
        serializer = ReportingPeriodSerializer(current_period)
        return Response(serializer.data)

class KPIDataCaptureView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            directorate = request.user.directorates.first()
            if not directorate:
                return Response(
                    {"error": "User not assigned to any directorate"},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Get current reporting period
            current_period = ReportingPeriod.objects.filter(
                is_active=True
            ).first()
            
            if not current_period:
                return Response(
                    {"error": "No active reporting period"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Check if it's within the open window
            today = timezone.now().date()
            if not (current_period.open_date <= today <= current_period.close_date):
                return Response(
                    {"error": "Active reporting period window is closed"},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Get predefined KPIs for this directorate and year
            predefined_kpis = PredefinedKPI.objects.filter(
                directorate=directorate,
                kpi_year__year=current_period.year  # Filter by reporting period year
            )
            
            # Get existing data
            kpi_actuals = KPIActual.objects.filter(
                directorate=directorate,
                year=current_period.year,
                month=current_period.month
            )
            
            # Get monthly targets
            monthly_targets = MonthlyTarget.objects.filter(
                predefined_kpi__directorate=directorate,
                predefined_kpi__kpi_year__year=current_period.year,  # Filter by year
                year=current_period.year,
                month=current_period.month
            )
            
            # Prepare response data
            data = []
            non_applicable_count = 0
            
            for kpi in predefined_kpis:
                actual = kpi_actuals.filter(predefined_kpi=kpi).first()
                target = monthly_targets.filter(predefined_kpi=kpi).first()
                
                is_applicable = target is not None
                if not is_applicable:
                    non_applicable_count += 1
                
                data.append({
                    'id': kpi.id,
                    'name': kpi.name,
                    'unit_of_measurement': kpi.unit_of_measurement,
                    'target_value': target.target_value if target else None,
                    'actual_value': actual.actual_value if actual else None,
                    'reason_for_performance': actual.reason_for_performance if actual else '',
                    'way_forward': actual.way_forward if actual else '',
                    'is_submitted': actual.is_submitted if actual else False,
                    'is_applicable': is_applicable,  # New field
                    'documents': [
                        {
                            'id': doc.id,
                            'file_name': doc.file_name,
                            'file_url': request.build_absolute_uri(doc.file.url),
                            'uploaded_at': doc.uploaded_at
                        } 
                        for doc in actual.documents.all()] if actual else []
                })
            
            return Response({
                'kpis': data,
                'non_applicable_count': non_applicable_count
            })
            
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    def post(self, request):
        try:
            # First find the active period (same as GET request)
            current_period = ReportingPeriod.objects.filter(
                is_active=True
            ).first()
            
            if not current_period:
                return Response(
                    {"error": "No active reporting period"},
                    status=status.HTTP_404_NOT_FOUND
                )
                
            # Then check if it's within the open window
            today = timezone.now().date()
            if not (current_period.open_date <= today <= current_period.close_date):
                return Response(
                    {"error": "Active reporting period window is closed"},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Get the user's first directorate
            directorate = request.user.directorates.first()
            if not directorate:
                return Response(
                    {"error": "User not assigned to any directorate"},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Handle both form data and JSON data
            if request.content_type == 'multipart/form-data':
                kpis_data = request.data.getlist('kpis[]') if 'kpis[]' in request.data else [request.data]
            else:
                kpis_data = request.data.get('kpis', [])
            
            saved_kpis = []
            errors = []
            
            for kpi_data in kpis_data:
                try:
                    kpi = PredefinedKPI.objects.get(
                        id=kpi_data.get('predefined_kpi_id'),
                        directorate=directorate  # Ensure KPI belongs to user's directorate
                    )
                    
                    # Convert actual_value to float if it exists
                    actual_value = kpi_data.get('actual_value')
                    if actual_value is not None and actual_value != '':
                        actual_value = float(actual_value)
                    else:
                        actual_value = None
                    
                    # Create or update the KPIActual
                    kpi_actual, created = KPIActual.objects.update_or_create(
                        predefined_kpi=kpi,
                        directorate=directorate,
                        year=current_period.year,  # Use active period's year
                        month=current_period.month,  # Use active period's month
                        defaults={
                            'actual_value': actual_value,
                            'reason_for_performance': kpi_data.get('reason_for_performance', ''),
                            'way_forward': kpi_data.get('way_forward', ''),
                            'is_submitted': kpi_data.get('is_submitted', False)
                        }
                    )
                    
                    saved_kpis.append({
                        'kpi_id': kpi.id,
                        'kpi_actual_id': kpi_actual.id
                    })
                    
                except Exception as e:
                    errors.append({
                        'kpi_id': kpi_data.get('predefined_kpi_id'),
                        'error': str(e)
                    })
            
            return Response({
                'status': 'success' if not errors else 'partial_success',
                'saved_kpis': saved_kpis,
                'errors': errors,
                'saved_count': len(saved_kpis),
                'reporting_period': {
                    'year': current_period.year,
                    'month': current_period.month
                }
            })
            
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

@method_decorator(csrf_exempt, name='dispatch')
class ExternalKPIDataView(APIView):
    """
    Highly secure API endpoint for external systems to access KPI data.
    Only allows GET requests and strictly limits data access.
    """
    authentication_classes = []
    permission_classes = []
    http_method_names = ['get']  # Only allow GET requests
    
    def get(self, request):
        # Get API key from headers only (more secure than query params)
        api_key = request.headers.get('X-API-KEY')
        if not api_key:
            return Response(
                {"error": "API key required in X-API-KEY header"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            key_record = APIKey.objects.get(key=api_key)
            
            # Validate key status
            if not key_record.is_active:
                return Response(
                    {"error": "API key is inactive"},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            if key_record.is_expired:
                return Response(
                    {"error": "API key has expired"},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Update last used timestamp
            key_record.last_used = timezone.now()
            key_record.save()
            
            # Apply strict rate limiting at view level
            if not self._check_rate_limit(request):
                return Response(
                    {"error": "Rate limit exceeded"},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
            
            # Validate and sanitize all input parameters
            try:
                year = int(request.query_params.get('year')) if request.query_params.get('year') else None
                month = int(request.query_params.get('month')) if request.query_params.get('month') else None
                directorate_id = int(request.query_params.get('directorate_id')) if request.query_params.get('directorate_id') else None
            except (ValueError, TypeError):
                return Response(
                    {"error": "Invalid parameter format - must be integers"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Build queryset with strict filtering
            queryset = KPIActual.objects.select_related(
                'predefined_kpi',
                'directorate'
            ).prefetch_related('documents').filter(
                is_submitted=True
            )
            
            if year:
                queryset = queryset.filter(year=year)
            if month:
                if month < 1 or month > 12:
                    return Response(
                        {"error": "Month must be between 1 and 12"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                queryset = queryset.filter(month=month)
            if directorate_id:
                queryset = queryset.filter(directorate_id=directorate_id)
            
            # Apply maximum limit to prevent excessive data requests
            MAX_RESULTS = 1000
            queryset = queryset[:MAX_RESULTS]
            
            serializer = ExternalKPISerializer(
                queryset,
                many=True,
                context={'request': request}
            )
            
            return Response({
                'count': queryset.count(),
                'results': serializer.data
            })
            
        except APIKey.DoesNotExist:
            return Response(
                {"error": "Invalid API key"},
                status=status.HTTP_403_FORBIDDEN
            )
        except Exception as e:
            # Generic error handler to prevent information leakage
            return Response(
                {"error": "An error occurred processing your request"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _check_rate_limit(self, request):
        """Simple rate limiting implementation"""
        # In production, consider using Django Ratelimit or similar
        return True  # Implement your rate limiting logic here

class AdminKPITargetView(APIView):
    permission_classes = [IsAdminOrStaff]
    
    def post(self, request):
        kpi_id = request.data.get('kpi_id')
        year = request.data.get('year')
        month = request.data.get('month')
        target_value = request.data.get('target_value')
        
        try:
            kpi = PredefinedKPI.objects.get(id=kpi_id)
            target, created = MonthlyTarget.objects.update_or_create(
                predefined_kpi=kpi,
                year=year,
                month=month,
                defaults={'target_value': target_value}
            )
            return Response({'status': 'success'})
        except Exception as e:
            return Response({'error': str(e)}, status=400)

class PreviousReportsView(generics.ListAPIView):
    serializer_class = KPIActualSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        try:
            directorate = self.request.user.directorate
        except AttributeError:
            return KPIActual.objects.none()
        
        queryset = KPIActual.objects.filter(
            directorate=directorate
        ).order_by('-year', '-month')
        
        year = self.request.query_params.get('year')
        month = self.request.query_params.get('month')
        
        if year:
            queryset = queryset.filter(year=year)
        if month:
            queryset = queryset.filter(month=month)
            
        return queryset

class AdminReportingPeriodView(generics.ListCreateAPIView):
    serializer_class = ReportingPeriodSerializer
    permission_classes = [IsAdminOrStaff]
    queryset = ReportingPeriod.objects.all().order_by('-year', '-month')
    def perform_create(self, serializer):
        # Ensure only one active period per month/year
        ReportingPeriod.objects.filter(
            year=serializer.validated_data['year'],
            month=serializer.validated_data['month']
        ).update(is_active=False)
        serializer.save(is_active=True)

    @action(detail=False, methods=['patch'])
    def deactivate_all(self, request):
        ReportingPeriod.objects.all().update(is_active=False)
        return Response({'status': 'success'})    
class AdminMonthlyTargetView(generics.ListCreateAPIView):
    serializer_class = MonthlyTargetSerializer
    permission_classes = [IsAdminOrStaff]
    
    def get_queryset(self):
        year = self.request.query_params.get('year')
        month = self.request.query_params.get('month')
        directorate_id = self.request.query_params.get('directorate_id')
        
        queryset = MonthlyTarget.objects.all()
        
        if year:
            queryset = queryset.filter(year=year)
        if month:
            queryset = queryset.filter(month=month)
        if directorate_id:
            queryset = queryset.filter(predefined_kpi__directorate_id=directorate_id)
        
        return queryset


class AdminReportingPeriodDetailView(APIView):
    permission_classes = [IsAdminOrStaff]
    
    def patch(self, request, pk):
        try:
            period = ReportingPeriod.objects.get(pk=pk)
            serializer = ReportingPeriodSerializer(period, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except ReportingPeriod.DoesNotExist:
            return Response({'error': 'Reporting period not found'}, status=status.HTTP_404_NOT_FOUND)
        
    def delete(self, request, pk):
        try:
            period = ReportingPeriod.objects.get(pk=pk)
            period.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except ReportingPeriod.DoesNotExist:
            return Response({'error': 'Reporting period not found'}, status=status.HTTP_404_NOT_FOUND)    

class DirectorateKPIsView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk):
        try:
            directorate = Directorate.objects.get(pk=pk)
            year = request.query_params.get('year')
            month = request.query_params.get('month')
            
            kpis = PredefinedKPI.objects.filter(directorate=directorate)
            
            if year and month:
                kpi_actuals = KPIActual.objects.filter(
                    directorate=directorate,
                    year=year,
                    month=month
                )
                
                data = []
                for kpi in kpis:
                    actual = kpi_actuals.filter(predefined_kpi=kpi).first()
                    data.append({
                        'predefined_kpi': PredefinedKPISerializer(kpi).data,
                        'is_submitted': actual.is_submitted if actual else False
                    })
                
                return Response(data)
            
            serializer = PredefinedKPISerializer(kpis, many=True)
            return Response(serializer.data)
        except Directorate.DoesNotExist:
            return Response(
                {"error": "Directorate not found"},
                status=status.HTTP_404_NOT_FOUND
            )       



class AdminKPISubmissionView(APIView):
    permission_classes = [IsAdminOrStaff]
    
    def get(self, request):
        year = request.query_params.get('year')
        month = request.query_params.get('month')
        
        if not year or not month:
            return Response(
                {"error": "Year and month parameters are required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get all directorates
        directorates = Directorate.objects.all()
        response_data = []
        total_non_applicable = 0
        
        for directorate in directorates:
            # Get predefined KPIs for this directorate and year
            predefined_kpis = PredefinedKPI.objects.filter(
                directorate=directorate,
                kpi_year__year=year  # Filter by year
            )
            
            # Get existing actual data
            kpi_actuals = KPIActual.objects.filter(
                directorate=directorate,
                year=year,
                month=month
            )
            
            # Get monthly targets to determine applicability
            monthly_targets = MonthlyTarget.objects.filter(
                predefined_kpi__directorate=directorate,
                predefined_kpi__kpi_year__year=year,  # Filter by year
                year=year,
                month=month
            )
            
            # Prepare directorate data
            directorate_data = {
                'directorate': DirectorateSerializer(directorate).data,
                'kpis': [],
                'submitted_count': 0,
                'total_count': predefined_kpis.count(),
                'non_applicable_count': 0
            }
            
            # Add KPI data
            for kpi in predefined_kpis:
                actual = kpi_actuals.filter(predefined_kpi=kpi).first()
                has_target = monthly_targets.filter(predefined_kpi=kpi).exists()
                
                if not has_target:
                    directorate_data['non_applicable_count'] += 1
                    total_non_applicable += 1
                
                directorate_data['kpis'].append({
                    'predefined_kpi': PredefinedKPISerializer(kpi).data,
                    'is_submitted': actual.is_submitted if actual else False,
                    'is_applicable': has_target  # New field to track applicability
                })
                
                if actual and actual.is_submitted and has_target:
                    directorate_data['submitted_count'] += 1
            
            response_data.append(directorate_data)
        
        return Response({
            'data': response_data,
            'non_applicable_kpis': total_non_applicable
        })


class KPIDocumentUploadView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request, kpi_actual_id):
        try:
            kpi_actual = KPIActual.objects.get(id=kpi_actual_id)
            
            # Verify user has permission to upload for this KPI
            if not request.user.directorates.filter(id=kpi_actual.directorate.id).exists():
                return Response(
                    {"error": "You don't have permission to upload documents for this KPI"},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Check if file exists in request
            if 'file' not in request.FILES:
                return Response(
                    {"error": "No file provided"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Additional security checks before even creating serializer
            file = request.FILES['file']
            
            # Check file size (5MB limit)
            max_size = 5 * 1024 * 1024  # 5MB
            if file.size > max_size:
                return Response(
                    {"error": f"File size exceeds the maximum limit of {max_size/1024/1024}MB"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check file extension
            valid_extensions = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png']
            ext = file.name.split('.')[-1].lower()
            if ext not in valid_extensions:
                return Response(
                    {"error": f"Unsupported file extension. Allowed extensions: {', '.join(valid_extensions)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check content type matches file extension
            valid_content_types = [
                'application/pdf',
                'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/vnd.ms-excel',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'application/vnd.ms-powerpoint',
                'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                'image/jpeg',
                'image/png'
            ]
            
            if file.content_type not in valid_content_types:
                return Response(
                    {"error": "Invalid file content type"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Sanitize filename
            import os
            from django.utils.text import get_valid_filename
            file.name = get_valid_filename(file.name)
            
            # Create serializer with request data
            serializer = KPIDocumentSerializer(
                data=request.data,
                context={'request': request}
            )
            
            if serializer.is_valid():
                # Save the document
                document = serializer.save(kpi_actual=kpi_actual)
                
                # Log the upload
                logger.info(
                    f"User {request.user.username} uploaded document {file.name} "
                    f"({file.size} bytes, {file.content_type}) for KPI {kpi_actual.id}. "
                    f"Document ID: {document.id}"
                )
                
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except KPIActual.DoesNotExist:
            logger.warning(f"Attempt to upload to non-existent KPI actual ID: {kpi_actual_id}")
            return Response(
                {"error": "KPI entry not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error uploading document: {str(e)}", exc_info=True)
            return Response(
                {"error": "An error occurred while uploading the file"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class InitiativeListView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = InitiativeSerializer
    
    def get_queryset(self):
        user = self.request.user
        directorate_id = self.request.query_params.get('directorate_id')
        year = self.request.query_params.get('year')
        
        queryset = Initiative.objects.all()
        
        # If user is not admin, filter by their directorates
        if not user.is_staff:
            queryset = queryset.filter(directorate__users=user)
        
        if directorate_id:
            queryset = queryset.filter(directorate_id=directorate_id)
        
        if year:
            queryset = queryset.filter(kpi_year__year=year)
        
        return queryset.select_related('directorate', 'kpi_year').prefetch_related('activities', 'linked_kpis')

class InitiativeDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = InitiativeSerializer
    queryset = Initiative.objects.all()
    
    def get_queryset(self):
        user = self.request.user
        if user.is_staff:
            return Initiative.objects.all()
        return Initiative.objects.filter(directorate__users=user)

class ActivityReportView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Get current reporting period
        current_period = ReportingPeriod.objects.filter(is_active=True).first()
        
        directorate_id = request.query_params.get('directorate_id')
        initiative_id = request.query_params.get('initiative_id')
        year = request.query_params.get('year', current_period.year if current_period else None)
        month = request.query_params.get('month', current_period.month if current_period else None)
        
        if not year or not month:
            return Response(
                {"error": "Year and month parameters are required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get activities based on filters
        activities = Activity.objects.all()
        
        if not request.user.is_staff:
            activities = activities.filter(initiative__directorate__users=request.user)
        
        if directorate_id:
            activities = activities.filter(initiative__directorate_id=directorate_id)
        
        if initiative_id:
            activities = activities.filter(initiative_id=initiative_id)
        
        # Prepare response data
        response_data = []
        
        for activity in activities:
            report = activity.reports.filter(year=year, month=month).first()
            
            response_data.append({
                'activity': ActivitySerializer(activity).data,
                'report': ActivityReportSerializer(report).data if report else None,
                'is_submitted': report.is_submitted if report else False
            })
        
        return Response(response_data)
    
    def post(self, request):
        activity_id = request.data.get('activity_id')
        year = request.data.get('year')
        month = request.data.get('month')
        status = request.data.get('status')
        
        try:
            activity = Activity.objects.get(id=activity_id)
            
            # Verify user has permission to report for this activity
            if not request.user.directorates.filter(id=activity.initiative.directorate.id).exists():
                return Response(
                    {"error": "You don't have permission to report for this activity"},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Create or update the report
            report, created = ActivityReport.objects.update_or_create(
                activity=activity,
                year=year,
                month=month,
                defaults={
                    'status': status,
                    'progress': request.data.get('progress', ''),
                    'challenges': request.data.get('challenges', ''),
                    'way_forward': request.data.get('way_forward', ''),
                    'is_submitted': request.data.get('is_submitted', False),
                    'submitted_by': request.user if request.data.get('is_submitted') else None
                }
            )
            
            return Response(ActivityReportSerializer(report).data)
            
        except Activity.DoesNotExist:
            return Response(
                {"error": "Activity not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        
class ActivityReportDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, report_id):
        try:
            report = ActivityReport.objects.get(id=report_id)
            
            # Verify user has permission
            if not request.user.is_staff and not request.user.directorates.filter(id=report.activity.initiative.directorate.id).exists():
                return Response(
                    {"error": "You don't have permission to update this report"},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            serializer = ActivityReportSerializer(report, data=request.data, partial=True)
            if serializer.is_valid():
                if 'is_submitted' in request.data and request.data['is_submitted']:
                    serializer.save(submitted_by=request.user, submitted_at=timezone.now())
                else:
                    serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except ActivityReport.DoesNotExist:
            return Response(
                {"error": "Report not found"},
                status=status.HTTP_404_NOT_FOUND
            )

class ActivityReportCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, activity_id):
        try:
            activity = Activity.objects.get(id=activity_id)
            
            # Verify user has permission
            if not request.user.is_staff and not request.user.directorates.filter(id=activity.initiative.directorate.id).exists():
                return Response(
                    {"error": "You don't have permission to create reports for this activity"},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            data = request.data.copy()
            data['activity'] = activity_id
            serializer = ActivityReportSerializer(data=data)
            
            if serializer.is_valid():
                if data.get('is_submitted', False):
                    serializer.save(submitted_by=request.user, submitted_at=timezone.now())
                else:
                    serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Activity.DoesNotExist:
            return Response(
                {"error": "Activity not found"},
                status=status.HTTP_404_NOT_FOUND
            )        

class InitiativeDashboardView(APIView):
    permission_classes = [IsAdminOrStaff]
    
    def get(self, request):
        year = request.query_params.get('year')
        month = request.query_params.get('month')
        
        if not year or not month:
            return Response(
                {"error": "Year and month parameters are required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get all directorates with their initiatives and reports
        directorates = Directorate.objects.all()
        response_data = []
        
        for directorate in directorates:
            initiatives = directorate.initiatives.all()
            directorate_data = {
                'directorate': DirectorateSerializer(directorate).data,
                'initiatives': [],
                'total_activities': 0,
                'submitted_reports': 0
            }
            
            for initiative in initiatives:
                activities = initiative.activities.all()
                initiative_data = {
                    'initiative': InitiativeSerializer(initiative).data,
                    'activities': [],
                    'submitted_count': 0
                }
                
                for activity in activities:
                    report = activity.reports.filter(year=year, month=month).first()
                    initiative_data['activities'].append({
                        'activity': ActivitySerializer(activity).data,
                        'report': ActivityReportSerializer(report).data if report else None,
                        'is_submitted': report.is_submitted if report else False
                    })
                    
                    if report and report.is_submitted:
                        initiative_data['submitted_count'] += 1
                        directorate_data['submitted_reports'] += 1
                
                directorate_data['total_activities'] += activities.count()
                directorate_data['initiatives'].append(initiative_data)
            
            response_data.append(directorate_data)
        
        return Response(response_data)   


class DirectorateInitiativesView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, directorate_id):
        try:
            # Get the directorate
            directorate = Directorate.objects.get(id=directorate_id)
            
            # Verify user has access to this directorate
            if not request.user.is_staff and not request.user.directorates.filter(id=directorate_id).exists():
                return Response(
                    {"error": "You don't have permission to view initiatives for this directorate"},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Get the year from query params
            year = request.query_params.get('year')
            
            # Get initiatives for this directorate
            initiatives = Initiative.objects.filter(
                directorate=directorate
            )
            
            if year:
                initiatives = initiatives.filter(kpi_year__year=year)
            
            # Include activities count and reported count for each initiative
            initiatives_data = []
            for initiative in initiatives:
                activities = initiative.activities.all()
                total_activities = activities.count()
                
                # Get current reporting period
                current_period = ReportingPeriod.objects.filter(is_active=True).first()
                
                reported_count = 0
                if current_period:
                    # Count how many activities have submitted reports for current period
                    reported_count = ActivityReport.objects.filter(
                        activity__initiative=initiative,
                        year=current_period.year,
                        month=current_period.month,
                        is_submitted=True
                    ).count()
                
                initiatives_data.append({
                    **InitiativeSerializer(initiative).data,
                    'activities_count': total_activities,
                    'reported_activities_count': reported_count
                })
            
            return Response(initiatives_data)
            
        except Directorate.DoesNotExist:
            return Response(
                {"error": "Directorate not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class InitiativeActivitiesView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, initiative_id):
        try:
            initiative = Initiative.objects.get(id=initiative_id)
            
            # Verify user has access to this initiative's directorate
            if not request.user.is_staff and not request.user.directorates.filter(id=initiative.directorate.id).exists():
                return Response(
                    {"error": "You don't have permission to view activities for this initiative"},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            year = request.query_params.get('year')
            month = request.query_params.get('month')
            
            if not year or not month:
                return Response(
                    {"error": "Both year and month parameters are required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                year = int(year)
                month = int(month)
                if month < 1 or month > 12:
                    raise ValueError("Month must be between 1 and 12")
            except ValueError as e:
                return Response(
                    {"error": str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            activities = initiative.activities.all()
            activities_data = []
            
            for activity in activities:
                report = activity.reports.filter(year=year, month=month).first()
                
                activities_data.append({
                    'id': activity.id,
                    'name': activity.name,
                    'description': activity.description,
                    'status': report.status if report else None,
                    'challenges': report.challenges if report else None,
                    'way_forward': report.way_forward if report else None,
                    'report_id': report.id if report else None,
                    'is_submitted': report.is_submitted if report else False,
                    'submitted_at': report.submitted_at if report else None
                })
            
            return Response(activities_data)
            
        except Initiative.DoesNotExist:
            return Response(
                {"error": "Initiative not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error fetching activities: {str(e)}", exc_info=True)
            return Response(
                {"error": "An error occurred while fetching activities"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminActivitySubmissionView(APIView):
    permission_classes = [IsAdminOrStaff]
    
    def get(self, request):
        year = request.query_params.get('year')
        month = request.query_params.get('month')
        
        if not year or not month:
            return Response(
                {"error": "Year and month parameters are required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get all directorates with their initiatives and activity reports
        directorates = Directorate.objects.all()
        response_data = []
        
        for directorate in directorates:
            initiatives = directorate.initiatives.all()
            directorate_data = {
                'directorate': DirectorateSerializer(directorate).data,
                'initiatives': [],
                'total_activities': 0,
                'submitted_activities': 0
            }
            
            for initiative in initiatives:
                activities = initiative.activities.all()
                initiative_data = {
                    'initiative': InitiativeSerializer(initiative).data,
                    'activities': [],
                    'submitted_count': 0
                }
                
                for activity in activities:
                    report = activity.reports.filter(year=year, month=month).first()
                    is_submitted = report.is_submitted if report else False
                    
                    initiative_data['activities'].append({
                        'id': activity.id,
                        'name': activity.name,
                        'is_submitted': is_submitted
                    })
                    
                    if is_submitted:
                        initiative_data['submitted_count'] += 1
                        directorate_data['submitted_activities'] += 1
                
                directorate_data['total_activities'] += activities.count()
                directorate_data['initiatives'].append(initiative_data)
            
            response_data.append(directorate_data)
        
        return Response(response_data)


class DirectorateReportView(APIView):
    permission_classes = [IsAdminOrStaff]
    
    def get(self, request):
        try:
            # Get parameters
            directorate_id = request.query_params.get('directorate_id')
            month = int(request.query_params.get('month'))
            year = int(request.query_params.get('year'))
            
            if not directorate_id or not month or not year:
                return Response(
                    {"error": "directorate_id, month and year are required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get previous month
            prev_month = month - 1 if month > 1 else 12
            prev_year = year if month > 1 else year - 1
            
            # Get directorate
            directorate = Directorate.objects.get(pk=directorate_id)
            
            # Prepare response data
            response_data = {
                'directorate': DirectorateSerializer(directorate).data,
                'year': year,
                'month': month,
                'initiatives': []
            }
            
            # Get all initiatives for this directorate
            initiatives = Initiative.objects.filter(
                directorate=directorate,
                kpi_year__year=year
            ).prefetch_related(
                'activities',
                'linked_kpis',
                'activities__reports'
            )
            
            for initiative in initiatives:
                initiative_data = {
                    'id': initiative.id,
                    'title': initiative.title,
                    'description': initiative.description,
                    'linked_kpis': [],
                    'activities': []
                }
                
                # Get KPI data for current and previous month
                for kpi in initiative.linked_kpis.all():
                    try:
                        current_target = MonthlyTarget.objects.get(
                            predefined_kpi=kpi,
                            year=year,
                            month=month
                        ).target_value
                    except MonthlyTarget.DoesNotExist:
                        current_target = None
                    
                    current_actual = KPIActual.objects.filter(
                        predefined_kpi=kpi,
                        year=year,
                        month=month
                    ).first()
                    
                    previous_actual = KPIActual.objects.filter(
                        predefined_kpi=kpi,
                        year=prev_year,
                        month=prev_month
                    ).first()
                    
                    initiative_data['linked_kpis'].append({
                        'id': kpi.id,
                        'name': kpi.name,
                        'unit_of_measurement': kpi.unit_of_measurement,
                        'current_target': current_target,
                        'current_actual': current_actual.actual_value if current_actual else None,
                        'previous_actual': previous_actual.actual_value if previous_actual else None,
                        'reason': current_actual.reason_for_performance if current_actual else None,
                        'way_forward': current_actual.way_forward if current_actual else None
                    })
                
                # Get activity data for current month
                for activity in initiative.activities.all():
                    report = activity.reports.filter(
                        year=year,
                        month=month
                    ).first()
                    
                    initiative_data['activities'].append({
                        'id': activity.id,
                        'name': activity.name,
                        'description': activity.description,
                        'status': report.status if report else 'grey',
                        'challenges': report.challenges if report else '',
                        'way_forward': report.way_forward if report else ''
                    })
                
                response_data['initiatives'].append(initiative_data)
            
            return Response(response_data)
            
        except Directorate.DoesNotExist:
            return Response(
                {"error": "Directorate not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error generating directorate report: {str(e)}", exc_info=True)
            return Response(
                {"error": "An error occurred while generating the report"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )