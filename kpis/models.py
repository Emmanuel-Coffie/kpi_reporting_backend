from django.db import models
from django.contrib.auth.models import User
from datetime import date, timedelta
from django.core.validators import MinValueValidator, MaxValueValidator
from django.core.validators import FileExtensionValidator
import hashlib

from django.db import models
from django.utils.crypto import get_random_string
from django.utils import timezone
from django.core.exceptions import ValidationError


class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('LOGIN', 'User login'),
        ('LOGOUT', 'User logout'),
        ('CREATE', 'Create operation'),
        ('UPDATE', 'Update operation'),
        ('DELETE', 'Delete operation'),
        ('ACCESS', 'Access operation'),
        ('AUTH_FAIL', 'Authentication failure'),
        ('TOKEN_REFRESH', 'Token refresh'),
        ('PASSWORD_CHANGE', 'Password change'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20)  # success, failed, etc.
    details = models.JSONField(default=dict)
    affected_object = models.CharField(max_length=255, null=True, blank=True)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    session_key = models.CharField(max_length=40, null=True, blank=True)
    request_headers = models.JSONField(default=dict)
    response_size = models.PositiveIntegerField(null=True, blank=True)
    processing_time = models.FloatField(null=True, blank=True)  # in milliseconds
    risk_score = models.PositiveSmallIntegerField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Audit Log'
        verbose_name_plural = 'Audit Logs'

    def __str__(self):
        return f"{self.timestamp} - {self.user} - {self.action} - {self.status}"
    

class CommunicationLog(models.Model):
    DIRECTION_CHOICES = [
        ('INBOUND', 'Inbound'),
        ('OUTBOUND', 'Outbound'),
    ]
    TYPE_CHOICES = [
        ('EMAIL', 'Email'),
        ('API', 'API Call'),
        ('NOTIFICATION', 'Notification'),
    ]

    direction = models.CharField(max_length=10, choices=DIRECTION_CHOICES)
    type = models.CharField(max_length=15, choices=TYPE_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    recipient = models.CharField(max_length=255, null=True, blank=True)
    subject = models.CharField(max_length=255, null=True, blank=True)
    content = models.TextField(null=True, blank=True)
    status = models.CharField(max_length=50)
    metadata = models.JSONField(default=dict)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Communication Log'
        verbose_name_plural = 'Communication Logs'

    def __str__(self):
        return f"{self.timestamp} - {self.direction} - {self.type} - {self.status}"
    
class RevokedCertificate(models.Model):
    REASON_CHOICES = [
        ('UNSPECIFIED', 'Unspecified'),
        ('KEY_COMPROMISE', 'Key compromise'),
        ('CA_COMPROMISE', 'CA compromise'),
        ('AFFILIATION_CHANGED', 'Affiliation changed'),
        ('SUPERSEDED', 'Superseded'),
        ('CESSATION_OF_OPERATION', 'Cessation of operation'),
        ('CERTIFICATE_HOLD', 'Certificate hold'),
        ('REMOVE_FROM_CRL', 'Remove from CRL'),
        ('PRIVILEGE_WITHDRAWN', 'Privilege withdrawn'),
        ('AA_COMPROMISE', 'AA compromise'),
    ]

    serial_number = models.CharField(max_length=128, unique=True)
    revocation_date = models.DateTimeField(auto_now_add=True)
    reason = models.CharField(max_length=30, choices=REASON_CHOICES, default='UNSPECIFIED')
    revoked_by = models.ForeignKey(User, on_delete=models.PROTECT)
    certificate = models.TextField(null=True, blank=True)  # PEM format
    last_checked = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = 'Revoked Certificate'
        verbose_name_plural = 'Revoked Certificates'
        indexes = [
            models.Index(fields=['serial_number']),
            models.Index(fields=['revocation_date']),
        ]

    def __str__(self):
        return f"Revoked certificate {self.serial_number} ({self.reason})"


class APIKey(models.Model):
    key = models.CharField(max_length=64, unique=True, editable=False)
    name = models.CharField(max_length=100, help_text="Identifier for the external system")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)
    expiry_date = models.DateField(null=True, blank=True)
    description = models.TextField(blank=True)
    
    class Meta:
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({'active' if self.is_active else 'inactive'})"
    
    def save(self, *args, **kwargs):
        if not self.key:
            self.key = get_random_string(64)
        super().save(*args, **kwargs)
    
    @property
    def is_expired(self):
        return self.expiry_date and self.expiry_date < timezone.now().date()
    
    @property
    def key_fingerprint(self):
        """Get SHA256 fingerprint of the key"""
        return hashlib.sha256(self.key.encode()).hexdigest()
    
    def rotate_key(self):
        """Rotate the API key"""
        old_key = self.key
        self.key = get_random_string(64)
        self.save()
        
        # Log the rotation
        from .models import AuditLog
        AuditLog.objects.create(
            user=None,
            action='KEY_ROTATION',
            status='SUCCESS',
            details={
                'key_id': self.id,
                'old_key_fingerprint': hashlib.sha256(old_key.encode()).hexdigest(),
                'new_key_fingerprint': self.key_fingerprint
            }
        )

class ReportingPeriod(models.Model):
    """Controls when users can report for specific months"""
    year = models.PositiveSmallIntegerField()
    month = models.PositiveSmallIntegerField(
        choices=[(i, f"{i:02d}") for i in range(1, 13)],
        validators=[MinValueValidator(1), MaxValueValidator(12)]
    )
    is_open = models.BooleanField(default=False)
    open_date = models.DateField()
    close_date = models.DateField()
    allow_user_targets = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    
    class Meta:
        unique_together = ('year', 'month')
        ordering = ['-year', '-month']
    
    def __str__(self):
        return f"{self.year}-{self.month:02d}"

class Directorate(models.Model):
    name = models.CharField(max_length=255)
    users = models.ManyToManyField(User, related_name='directorates', blank=True)
    
    def __str__(self):
        return self.name

class KPIYear(models.Model):
    """Represents a year's KPI configuration"""
    year = models.PositiveSmallIntegerField(unique=True)
    is_current = models.BooleanField(default=False)
    
    def __str__(self):
        return str(self.year)

class PredefinedKPI(models.Model):
    """KPI definitions for a specific year"""
    AGGREGATION_CHOICES = [
        ('SUM', 'Sum'),
        ('AVG', 'Average'),
    ]
    
    PERFORMANCE_LOGIC_CHOICES = [
        ('HIGHER', 'Higher is better'),
        ('LOWER', 'Lower is better'),
    ]
    
    kpi_year = models.ForeignKey(KPIYear, on_delete=models.CASCADE)
    directorate = models.ForeignKey(Directorate, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    unit_of_measurement = models.CharField(max_length=50)
    aggregation_type = models.CharField(
        max_length=3,
        choices=AGGREGATION_CHOICES,
        default='SUM',
        help_text="How to aggregate this KPI across directorates"
    )
    performance_logic = models.CharField(
        max_length=6,
        choices=PERFORMANCE_LOGIC_CHOICES,
        default='HIGHER',
        help_text="Performance evaluation logic"
    )
    is_corporate = models.BooleanField(
        default=False,
        help_text="Whether this is a corporate-level KPI"
    )
    
    class Meta:
        unique_together = ('kpi_year', 'directorate', 'name')
    
    def __str__(self):
        return f"{self.name} ({self.directorate.name} - {self.kpi_year.year})"
class MonthlyTarget(models.Model):
    """Monthly targets for each KPI"""
    predefined_kpi = models.ForeignKey(PredefinedKPI, on_delete=models.CASCADE)
    year = models.PositiveSmallIntegerField()
    month = models.PositiveSmallIntegerField(
        choices=[(i, f"{i:02d}") for i in range(1, 13)],
        validators=[MinValueValidator(1), MaxValueValidator(12)]
    )
    target_value = models.FloatField()
    
    class Meta:
        unique_together = ('predefined_kpi', 'year', 'month')
    
    def __str__(self):
        return f"{self.predefined_kpi.name} - {self.year}-{self.month:02d} Target"

class KPIActual(models.Model):
    """Actual reported values"""
    predefined_kpi = models.ForeignKey(PredefinedKPI, on_delete=models.CASCADE)
    directorate = models.ForeignKey(Directorate, on_delete=models.CASCADE)
    year = models.PositiveSmallIntegerField()
    month = models.PositiveSmallIntegerField(
        choices=[(i, f"{i:02d}") for i in range(1, 13)],
        validators=[MinValueValidator(1), MaxValueValidator(12)]
    )
    actual_value = models.FloatField(null=True, blank=True)
    reason_for_performance = models.TextField(blank=True)
    way_forward = models.TextField(blank=True)
    is_submitted = models.BooleanField(default=False)
    last_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('predefined_kpi', 'directorate', 'year', 'month')
        verbose_name = "Monthly KPI Entry"
        verbose_name_plural = "Monthly KPI Entries"
    
    def __str__(self):
        return f"{self.predefined_kpi.name} - {self.year}-{self.month:02d}"


class KPIDocument(models.Model):
    kpi_actual = models.ForeignKey(KPIActual, on_delete=models.CASCADE, related_name='documents')
    file = models.FileField(upload_to='kpi_documents/')
    file_name = models.CharField(max_length=255)
    file_type = models.CharField(max_length=500)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return f"Document for {self.kpi_actual} - {self.file_name}"     
    file = models.FileField(
        upload_to='kpi_documents/',
        validators=[
            FileExtensionValidator(
                allowed_extensions=['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png']
            )
        ],
        max_length=255
    )
    
    # Add file size field
    file_size = models.PositiveIntegerField(editable=False, null=True, blank=True)
    
    def save(self, *args, **kwargs):
        # Calculate and save file size before saving
        if self.file:
            self.file_size = self.file.size
        super().save(*args, **kwargs)
    
    def clean(self):
        # Validate file size (5MB limit)
        max_size = 5 * 1024 * 1024  # 5MB
        if self.file and self.file.size > max_size:
            raise ValidationError(f"File size exceeds the maximum limit of {max_size/1024/1024}MB")   
        
# Add to models.py
class TwoFactorAuth(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=False)
    email = models.EmailField(blank=True)
    last_code = models.CharField(max_length=6, blank=True)
    code_expiry = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def generate_code(self):
        # Generate a 6-digit code
        code = get_random_string(6, allowed_chars='0123456789')
        self.last_code = code
        self.code_expiry = timezone.now() + timedelta(minutes=10)  # Code expires in 10 minutes
        self.save()
        return code

    def is_code_valid(self, code):
        return (
            self.last_code == code and 
            self.code_expiry and 
            timezone.now() < self.code_expiry
        )        

def validate_month(value):
    if value < 1 or value > 12:
        raise ValidationError("Month must be between 1 and 12")

def validate_year(value):
    if value < 2000 or value > 2100:
        raise ValidationError("Year must be between 2000 and 2100")

class Initiative(models.Model):
    directorate = models.ForeignKey(Directorate, on_delete=models.CASCADE, related_name='initiatives')
    kpi_year = models.ForeignKey(KPIYear, on_delete=models.CASCADE, null=True, blank=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    start_date = models.DateField()
    end_date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    linked_kpis = models.ManyToManyField(
        PredefinedKPI, 
        blank=True, 
        related_name='initiatives',
        help_text="Regular KPIs linked to this initiative"
    )
    corporate_kpis = models.ManyToManyField(
        PredefinedKPI,
        blank=True,
        related_name='corporate_initiatives',
        limit_choices_to={'is_corporate': True},
        help_text="Corporate KPIs linked to this initiative"
    )

    class Meta:
        ordering = ['-start_date']
        unique_together = ('directorate', 'title', 'kpi_year')

    def __str__(self):
        return f"{self.title} ({self.directorate.name})"
    
class Activity(models.Model):
    STATUS_CHOICES = [
        ('red', 'At Risk'),
        ('yellow', 'On Track'),
        ('green', 'Completed'),
        ('grey', 'On Hold'),
        ('pink', 'Needs Attention'),
    ]

    initiative = models.ForeignKey(Initiative, on_delete=models.CASCADE, related_name='activities')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Activities"
        unique_together = ('initiative', 'name')

    def __str__(self):
        return f"{self.initiative.title} - {self.name}"

class ActivityReport(models.Model):
    activity = models.ForeignKey(Activity, on_delete=models.CASCADE, related_name='reports')
    month = models.IntegerField(validators=[validate_month])
    year = models.IntegerField(validators=[validate_year])
    status = models.CharField(max_length=10, choices=Activity.STATUS_CHOICES)
    challenges = models.TextField(blank=True)
    way_forward = models.TextField(blank=True)
    is_submitted = models.BooleanField(default=False)
    submitted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('activity', 'year', 'month')
        ordering = ['-year', '-month']

    def __str__(self):
        return f"{self.activity.name} - {self.year}-{self.month:02d}"

    def save(self, *args, **kwargs):
        if self.is_submitted and not self.submitted_at:
            self.submitted_at = timezone.now()
        super().save(*args, **kwargs)
