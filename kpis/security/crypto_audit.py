import os
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from django.core.management.base import BaseCommand
from django.conf import settings
from datetime import datetime
from ..models import RevokedCertificate, APIKey

class CryptographicAuditor:
    def check_certificates(self):
        """Check all certificates in the system"""
        revoked_certs = RevokedCertificate.objects.all()
        issues = []
        
        for cert in revoked_certs:
            try:
                x509_cert = load_pem_x509_certificate(
                    cert.certificate.encode('utf-8')
                )
                # Check certificate validity period
                if x509_cert.not_valid_after < datetime.now():
                    issues.append(f"Revoked certificate {cert.serial_number} has expired")
                
            except Exception as e:
                issues.append(f"Error processing certificate {cert.serial_number}: {str(e)}")
        
        return issues
    
    def check_apikeys(self):
        """Check API key security"""
        issues = []
        for key in APIKey.objects.all():
            if len(key.key) < 32:
                issues.append(f"API key {key.name} is too short")
            if key.is_expired:
                issues.append(f"API key {key.name} is expired but still active")
        
        return issues
    
    def check_configuration(self):
        """Check cryptographic configuration"""
        issues = []
        
        # Check secret key
        if settings.SECRET_KEY == 'django-insecure-default-key':
            issues.append("Default SECRET_KEY in use")
        
        # Check JWT algorithm
        if settings.SIMPLE_JWT.get('ALGORITHM', 'HS256') != 'HS256':
            issues.append("JWT algorithm should be HS256 for maximum security")
        
        return issues

class Command(BaseCommand):
    help = 'Perform cryptographic audit'
    
    def handle(self, *args, **options):
        auditor = CryptographicAuditor()
        
        cert_issues = auditor.check_certificates()
        key_issues = auditor.check_apikeys()
        config_issues = auditor.check_configuration()
        
        all_issues = cert_issues + key_issues + config_issues
        
        if all_issues:
            self.stdout.write(self.style.ERROR('Cryptographic issues found:'))
            for issue in all_issues:
                self.stdout.write(f"- {issue}")
        else:
            self.stdout.write(self.style.SUCCESS('No cryptographic issues found'))