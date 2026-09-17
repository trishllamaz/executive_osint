"""
normalize.py
Validates and normalizes email addresses and phone numbers before
they're passed into any lookup module. Bad input wastes API calls
and produces noisy/incorrect reports, so we fail fast here.
"""

import phonenumbers
from phonenumbers import NumberParseException, geocoder, carrier as phone_carrier
from email_validator import validate_email, EmailNotValidError


def normalize_email(raw_email: str) -> dict:
    """Returns {'valid': bool, 'email': str|None, 'error': str|None}"""
    try:
        result = validate_email(raw_email, check_deliverability=False)
        return {"valid": True, "email": result.normalized, "error": None}
    except EmailNotValidError as e:
        return {"valid": False, "email": None, "error": str(e)}


def normalize_phone(raw_phone: str, default_region: str = "US") -> dict:
    """
    Returns {'valid': bool, 'e164': str|None, 'country': str|None,
              'location': str|None, 'carrier': str|None, 'error': str|None}
    default_region is used only if the number has no country code.
    """
    try:
        parsed = phonenumbers.parse(raw_phone, default_region)
        if not phonenumbers.is_valid_number(parsed):
            return {"valid": False, "e164": None, "country": None,
                    "location": None, "carrier": None, "error": "Number failed validity check"}

        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        region = phonenumbers.region_code_for_number(parsed)
        location = geocoder.description_for_number(parsed, "en")
        carrier_name = phone_carrier.name_for_number(parsed, "en")

        return {
            "valid": True,
            "e164": e164,
            "country": region,
            "location": location or None,
            "carrier": carrier_name or None,
            "error": None,
        }
    except NumberParseException as e:
        return {"valid": False, "e164": None, "country": None,
                "location": None, "carrier": None, "error": str(e)}


if __name__ == "__main__":
    # Quick manual test
    print(normalize_email("exec@example.com"))
    print(normalize_phone("+1 415 555 0132"))
