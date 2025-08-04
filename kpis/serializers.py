from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
import os

from .models import (PredefinedKPI, KPIActual, Directorate, 
                    MonthlyTarget, ReportingPeriod,KPIDocument,RevokedCertificate,CommunicationLog
                    ,AuditLog,ActivityReport,Activity, Initiative)


class TwoFactorVerifySerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6, min_length=6)
    temp_access = serializers.CharField()
    temp_refresh = serializers.CharField()

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        
        # Add password reset flag if it's the first login
        if check_password('defaultpassword', self.user.password):  # Or any condition you want
            data['requires_password_reset'] = True
        
        data.update({
            'username': self.user.username,
            'user_id': self.user.id,
            'is_staff': self.user.is_staff,
            'is_superuser': self.user.is_superuser,
        })
        
        # Add directorates info if exists
        directorates = self.user.directorates.all()
        if directorates.exists():
            data['directorates'] = DirectorateSerializer(directorates, many=True).data
        return data
    




class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'is_staff']
        read_only_fields = ['id', 'is_staff']


class DirectorateSerializer(serializers.ModelSerializer):
    users = UserSerializer(many=True, read_only=True)

    class Meta:
        model = Directorate
        fields = ['id', 'name', 'users']

class PredefinedKPISerializer(serializers.ModelSerializer):
    directorate = DirectorateSerializer(read_only=True)
    
    class Meta:
        model = PredefinedKPI
        fields = [
            'id', 
            'name', 
            'directorate', 
            'unit_of_measurement',
            'aggregation_type',
            'performance_logic',
            'is_corporate'
        ]
        
class MonthlyTargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = MonthlyTarget
        fields = ['id', 'predefined_kpi', 'year', 'month', 'target_value']



class ReportingPeriodSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportingPeriod
        fields = ['id', 'year', 'month', 'is_open', 'open_date', 'close_date', 'allow_user_targets', 'is_active']



class AdminKPISubmissionSerializer(serializers.ModelSerializer):
    predefined_kpi = PredefinedKPISerializer(read_only=True)
    is_submitted = serializers.BooleanField()
    
    class Meta:
        model = KPIActual
        fields = ['predefined_kpi', 'is_submitted']      

class KPIDocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = KPIDocument
        fields = ['id', 'file', 'file_name', 'file_type', 'uploaded_at', 'file_size']
        read_only_fields = ['file_name', 'file_type', 'uploaded_at', 'file_size']

    def validate_file(self, value):
        """
        Custom validation for the file field
        """
        # Check file size (5MB limit)
        max_size = 5 * 1024 * 1024  # 5MB
        if value.size > max_size:
            raise serializers.ValidationError(f"File size exceeds the maximum limit of {max_size/1024/1024}MB")
        
        # Check file extension
        valid_extensions = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png']
        ext = value.name.split('.')[-1].lower()
        if ext not in valid_extensions:
            raise serializers.ValidationError(f"Unsupported file extension. Allowed extensions: {', '.join(valid_extensions)}")
        
        return value

    def create(self, validated_data):
        file = validated_data.get('file')
        validated_data['file_name'] = file.name
        validated_data['file_type'] = file.content_type
        validated_data['uploaded_by'] = self.context['request'].user
        
        # Calculate file size
        validated_data['file_size'] = file.size
        
        # Sanitize filename
        filename = os.path.basename(file.name)
        filename = "".join(c for c in filename if c.isalnum() or c in (' ', '.', '_', '-'))
        validated_data['file_name'] = filename
        
        return super().create(validated_data)   

class ExternalKPISerializer(serializers.ModelSerializer):
    directorate_name = serializers.CharField(source='directorate.name')
    kpi_name = serializers.CharField(source='predefined_kpi.name')
    unit_of_measurement = serializers.CharField(source='predefined_kpi.unit_of_measurement')
    target_value = serializers.SerializerMethodField()
    documents = serializers.SerializerMethodField()
    
    class Meta:
        model = KPIActual
        fields = [
            'directorate_name',
            'kpi_name',
            'unit_of_measurement',
            'year',
            'month',
            'target_value',
            'actual_value',
            'reason_for_performance',
            'way_forward',
            'documents',
            'last_updated',
        ]
    
    def get_target_value(self, obj):
        try:
            target = MonthlyTarget.objects.get(
                predefined_kpi=obj.predefined_kpi,
                year=obj.year,
                month=obj.month
            )
            return target.target_value
        except MonthlyTarget.DoesNotExist:
            return None
    
    def get_documents(self, obj):
        request = self.context.get('request')
        return [
            {
                'file_name': doc.file_name,
                'file_url': request.build_absolute_uri(doc.file.url) if request else doc.file.url,
                'uploaded_at': doc.uploaded_at
            }
            for doc in obj.documents.all()
        ]
    

# serializers.py
class KPIActualSerializer(serializers.ModelSerializer):
    predefined_kpi = PredefinedKPISerializer(read_only=True)
    monthly_target = serializers.SerializerMethodField()
    documents = KPIDocumentSerializer(many=True, read_only=True)
    
    class Meta:
        model = KPIActual
        fields = [
            'id', 'predefined_kpi', 'directorate', 'year', 'month',
            'actual_value', 'monthly_target', 'reason_for_performance',
            'way_forward', 'is_submitted', 'last_updated', 'documents'
        ]
        read_only_fields = ['directorate', 'is_submitted', 'last_updated']
    
    def get_monthly_target(self, obj):
        try:
            target = MonthlyTarget.objects.get(
                predefined_kpi=obj.predefined_kpi,
                year=obj.year,
                month=obj.month
            )
            return target.target_value
        except MonthlyTarget.DoesNotExist:
            return None


class AuditLogSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'user', 'action', 'ip_address', 'timestamp',
            'status', 'details', 'affected_object', 'object_id'
        ]
        read_only_fields = fields

class CommunicationLogSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = CommunicationLog
        fields = [
            'id', 'direction', 'type', 'timestamp', 'user',
            'recipient', 'subject', 'content', 'status', 'metadata'
        ]
        read_only_fields = fields

class RevokedCertificateSerializer(serializers.ModelSerializer):
    revoked_by = UserSerializer(read_only=True)
    
    class Meta:
        model = RevokedCertificate
        fields = [
            'id', 'serial_number', 'revocation_date', 'reason',
            'revoked_by', 'certificate', 'last_checked'
        ]
        read_only_fields = ['revocation_date', 'revoked_by', 'last_checked']


class ActivityReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActivityReport
        fields = [
            'id', 'activity', 'year', 'month', 'status', 
            'challenges', 'way_forward',
            'is_submitted', 'submitted_at', 'last_updated'
        ]
        read_only_fields = ['submitted_at', 'last_updated']

class ActivitySerializer(serializers.ModelSerializer):
    reports = serializers.SerializerMethodField()
    
    class Meta:
        model = Activity
        fields = [
            'id', 'name', 'description', 
            'initiative', 'reports'
        ]
    
    def get_reports(self, obj):
        request = self.context.get('request')
        year = request.query_params.get('year') if request else None
        month = request.query_params.get('month') if request else None
        
        queryset = obj.reports.all()
        if year:
            queryset = queryset.filter(year=year)
        if month:
            queryset = queryset.filter(month=month)
            
        return ActivityReportSerializer(queryset, many=True).data

class InitiativeSerializer(serializers.ModelSerializer):
    activities = ActivitySerializer(many=True, read_only=True)
    linked_kpis = PredefinedKPISerializer(many=True, read_only=True)
    corporate_kpis = PredefinedKPISerializer(many=True, read_only=True)
    directorate = DirectorateSerializer(read_only=True)
    
    class Meta:
        model = Initiative
        fields = [
            'id', 'title', 'description', 'directorate',
            'kpi_year', 'start_date', 'end_date',
            'activities', 'linked_kpis', 'corporate_kpis'
        ]