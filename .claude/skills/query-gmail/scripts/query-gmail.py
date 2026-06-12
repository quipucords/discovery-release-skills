#!/usr/bin/env python3
# /// script
# dependencies = [
#     "google-auth>=2.36.0",
#     "google-auth-oauthlib>=1.2.1",
#     "google-auth-httplib2>=0.2.0",
#     "google-api-python-client>=2.154.0",
# ]
# ///
"""
Standalone Gmail query script with command-line interface.

This script queries Gmail messages based on various filters and outputs results as JSON.
All logs and errors go to stderr; only JSON results go to stdout.
"""

import argparse
import base64
import json
import os
import re
import sys
from email.utils import parsedate_to_datetime
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


# Gmail API scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def log(message: str) -> None:
    """Log to stderr."""
    print(message, file=sys.stderr)


def get_credentials_path() -> Path:
    """Get path to Gmail credentials file from environment variable or default location."""
    creds_path = os.getenv("GMAIL_CREDENTIALS_PATH", "~/.config/gmail/credentials.json")
    path = Path(creds_path).expanduser()

    if not path.exists():
        raise FileNotFoundError(
            f"Gmail credentials not found at {path}. "
            "Please set GMAIL_CREDENTIALS_PATH environment variable or place credentials at default location."
        )

    return path


def get_token_path() -> Path:
    """Get path to Gmail token file from environment variable or default location."""
    token_path = os.getenv("GMAIL_TOKEN_PATH", "~/.config/gmail/token.json")
    path = Path(token_path).expanduser()
    return path  # Return even if doesn't exist yet (will be created on first auth)


def get_gmail_service():
    """Authenticate and return Gmail API service."""
    creds = None
    token_path = get_token_path()
    credentials_path = get_credentials_path()

    # Check for existing token
    if token_path.exists():
        log(f"Loading credentials from {token_path}")
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)

    # If no valid credentials, authenticate
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            log("Refreshing expired credentials...")
            creds.refresh(Request())
        else:
            log(f"Authenticating with credentials from {credentials_path}")
            flow = InstalledAppFlow.from_client_secrets_file(
                str(credentials_path), SCOPES)
            creds = flow.run_local_server(port=0)

        # Save credentials for next run
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(creds.to_json())
        log(f"Credentials saved to {token_path}")

    return build('gmail', 'v1', credentials=creds)


def get_message_body(payload: dict) -> str:
    """Extract message body from Gmail API payload."""
    body = ""

    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                if 'data' in part['body']:
                    body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    break
            elif part['mimeType'] == 'text/html' and not body:
                # Fallback to HTML if no plain text
                if 'data' in part['body']:
                    body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
            elif 'parts' in part:
                # Recursive for nested parts
                body = get_message_body(part)
                if body:
                    break
    else:
        if 'body' in payload and 'data' in payload['body']:
            body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')

    return body


def build_query(
    label: str | None = None,
    from_address: str | None = None,
    to_or_cc: str | None = None,
    subject_regex: str | None = None,
    since_date: str | None = None,
) -> str:
    """Build Gmail search query from filters."""
    query_parts = []

    if label:
        query_parts.append(f'label:"{label}"')

    if from_address:
        query_parts.append(f'from:{from_address}')

    if to_or_cc:
        # Gmail's OR operator for to/cc
        query_parts.append(f'(to:{to_or_cc} OR cc:{to_or_cc})')

    if since_date:
        # Gmail expects date format like after:YYYY/MM/DD
        date_formatted = since_date.replace('-', '/')
        query_parts.append(f'after:{date_formatted}')

    # Note: subject_regex is applied as post-filter since Gmail doesn't support regex
    # For basic subject matching without regex, we could add: subject:"text"
    # But we'll filter in Python to support full regex

    return ' '.join(query_parts) if query_parts else None


def query_gmail(
    service,
    label: str | None = None,
    max_results: int = 100,
    from_address: str | None = None,
    to_or_cc: str | None = None,
    subject_regex: str | None = None,
    since_date: str | None = None,
) -> dict:
    """Query Gmail and return matching messages."""
    # Build Gmail query (without regex filter)
    query = build_query(label, from_address, to_or_cc, None, since_date)

    log(f"Gmail query: {query if query else '(no filters)'}")

    # Compile subject regex if provided
    subject_pattern = None
    if subject_regex:
        try:
            subject_pattern = re.compile(subject_regex)
            log(f"Subject regex: {subject_regex}")
        except re.error as e:
            log(f"ERROR: Invalid subject regex: {e}")
            return {"messages": []}

    try:
        # Search for messages
        results = service.users().messages().list(
            userId='me',
            q=query,
            maxResults=max_results
        ).execute()

        messages = results.get('messages', [])
        log(f"Found {len(messages)} messages from Gmail query")

        if not messages:
            return {"messages": []}

        # Get full details for each message
        output_messages = []
        for msg in messages:
            try:
                msg_data = service.users().messages().get(
                    userId='me',
                    id=msg['id'],
                    format='full'
                ).execute()

                headers = {h['name']: h['value'] for h in msg_data['payload']['headers']}

                subject = headers.get('Subject', 'No Subject')

                # Apply subject regex filter if provided
                if subject_pattern and not subject_pattern.search(subject):
                    log(f"Skipping message (subject regex mismatch): {subject}")
                    continue

                # Parse date
                date_str = headers.get('Date', '')
                try:
                    msg_date = parsedate_to_datetime(date_str)
                    date_formatted = msg_date.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    date_formatted = date_str

                # Get message body
                body = get_message_body(msg_data['payload'])

                output_messages.append({
                    "message_id": msg['id'],
                    "subject": subject,
                    "from": headers.get('From', 'Unknown'),
                    "to": headers.get('To', 'Unknown'),
                    "cc": headers.get('Cc', ''),
                    "date": date_formatted,
                    "body": body,
                    "labels": msg_data.get('labelIds', []),
                })

            except Exception as e:
                log(f"ERROR: Failed to retrieve message {msg['id']}: {e}")
                continue

        log(f"Returning {len(output_messages)} messages after filtering")
        return {"messages": output_messages}

    except Exception as e:
        # Re-raise so main() can catch it and exit non-zero.
        # Returning {"messages": []} here would make network/auth failures
        # look like "zero emails found" and silently propagate empty data.
        raise RuntimeError(f"Failed to query Gmail: {e}") from e


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Query Gmail messages with various filters and output JSON results.",
        epilog="""
OUTPUT FORMAT:
  JSON object with "messages" array, each containing:
    - message_id: Gmail message ID
    - subject: Email subject line
    - from: Sender email address
    - to: Recipient email address(es)
    - cc: CC email address(es)
    - date: Email date (YYYY-MM-DD HH:MM:SS)
    - body: Full email body (plain text or HTML)
    - labels: Array of Gmail label IDs

EXAMPLES:
  # Query Prograde emails from last 30 days
  %(prog)s --label "$PROGRADE_LABEL" --since "2026-05-03"

  # Query emails from specific sender
  %(prog)s --from "$PROGRADE_SENDER" --max-results 50

  # Query with subject regex
  %(prog)s --subject-regex "\\[Prograde\\].*Important" --since "2026-04-01"

  # Pipe to parse-prograde-advisories.py
  %(prog)s --label "$PROGRADE_LABEL" --since "2026-05-01" | parse-prograde-advisories.py

  # Save to file for later processing
  %(prog)s --label "$PROGRADE_LABEL" --since "2026-05-01" > prograde-emails.json

AUTHENTICATION:
  Uses Gmail API with OAuth2. Credentials path:
    - Default: ~/.config/gmail/credentials.json
    - Override: GMAIL_CREDENTIALS_PATH environment variable
  Token saved to:
    - Default: ~/.config/gmail/token.json
    - Override: GMAIL_TOKEN_PATH environment variable

NOTE:
  All logs and error messages go to stderr.
  Only JSON output goes to stdout.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        '--label',
        metavar='LABEL',
        help='Gmail label to filter by (e.g., "alerts/prograde")',
    )
    parser.add_argument(
        '--max-results',
        type=int,
        default=100,
        metavar='N',
        help='Maximum number of messages to retrieve (default: 100)',
    )
    parser.add_argument(
        '--from',
        dest='from_address',
        metavar='EMAIL',
        help='Filter by sender email address',
    )
    parser.add_argument(
        '--to-or-cc',
        metavar='EMAIL',
        help='Filter by recipient in To or CC field',
    )
    parser.add_argument(
        '--subject-regex',
        metavar='PATTERN',
        help='Filter by subject using regex pattern',
    )
    parser.add_argument(
        '--since',
        dest='since_date',
        metavar='YYYY-MM-DD',
        help='Filter messages since date (format: YYYY-MM-DD, inclusive)',
    )

    args = parser.parse_args()

    try:
        service = get_gmail_service()
        result = query_gmail(
            service,
            label=args.label,
            max_results=args.max_results,
            from_address=args.from_address,
            to_or_cc=args.to_or_cc,
            subject_regex=args.subject_regex,
            since_date=args.since_date,
        )

        # Output JSON to stdout (only this goes to stdout!)
        print(json.dumps(result, indent=2))

    except Exception as e:
        log(f"FATAL ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
