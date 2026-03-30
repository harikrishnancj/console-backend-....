from email_validator import validate_email, EmailNotValidError
import dns.resolver
from fastapi import HTTPException


def validate_email_address(email: str) -> str:
    
    if not email:
        raise HTTPException(
            status_code=400,
            detail="Email is required"
        )
    
    try:
        email_info = validate_email(email, check_deliverability=False)
        normalized_email = email_info.normalized
        domain = email_info.domain
    except EmailNotValidError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid email format: {str(e)}"
        )
    
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        if not mx_records:
            raise HTTPException(
                status_code=400,
                detail="Email domain does not accept emails"
            )
    except dns.resolver.NXDOMAIN:
        raise HTTPException(
            status_code=400,
            detail="Email domain does not exist"
        )
    except dns.resolver.NoAnswer:
        raise HTTPException(
            status_code=400,
            detail="Email domain has no mail server configured"
        )
    except dns.resolver.Timeout:
        raise HTTPException(
            status_code=400,
            detail="Could not verify email domain. Please try again."
        )
    except dns.resolver.NoNameservers:
        raise HTTPException(
            status_code=400,
            detail="Email domain DNS is not reachable"
        )
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Email validation failed: {str(e)}"
        )
    
    return normalized_email
