"""Generic ArcSight CEF detection adapter (C1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

CEF is the lowest common denominator: almost every appliance that has existed
since 2006 can emit it, which makes one adapter cover the long tail of firewall,
WAF, proxy and legacy IDS products a site already owns.

    CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|key=value key=value

Two properties of the format need care and are the reason this is a hand-written
parser rather than a split on ``|`` and ``=``:

1. **Pipes and equals signs are escaped, not forbidden.** ``\\|`` inside the
   name field and ``\\=`` inside an extension value are legal, and splitting
   naively truncates a rule name at the first escaped pipe.
2. **Extension values may contain spaces.** ``msg=login failed src=10.0.0.1``
   is one key with a two-word value followed by another key — so the parser has
   to look ahead for the next ``key=`` rather than split on whitespace.

Severity is 0-10 here, which the contract's normaliser reads as its ``> 15``
branch would misclassify, so it is rescaled explicitly.
"""
from __future__ import annotations

import re
from typing import Any, Dict

from detection import (
    Detection,
    DetectionAdapter,
    DetectionParseError,
    normalize_severity,
    parse_timestamp,
)

_CEF_PREFIX = re.compile(r'^\s*CEF:\d+\|')
#: A key is a bare word followed by '='; used to find where each value ends.
_KEY = re.compile(r'(?<!\\)\b([A-Za-z][A-Za-z0-9_]*)=')


#: CEF:<ver>|Vendor|Product|Version|SignatureID|Name|Severity|extension — eight
#: fields, and only the first seven are pipe-delimited. The extension may
#: contain bare pipes (the spec does not require escaping them there), so the
#: split has to stop rather than keep going.
_HEADER_FIELDS = 8


def _split_header(line: str, limit: int = _HEADER_FIELDS) -> list:
    """Split on unescaped pipes, then unescape. `\\|` stays inside its field."""
    fields, current, escaped = [], [], False
    for index, char in enumerate(line):
        if escaped:
            current.append(char)
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == '|' and len(fields) < limit - 1:
            fields.append(''.join(current))
            current = []
        else:
            current.append(char)
    fields.append(''.join(current))
    return fields


def _parse_extension(text: str) -> Dict[str, str]:
    """`k=v k=v` where a value may contain spaces but a key may not."""
    matches = list(_KEY.finditer(text))
    extension: Dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        value = text[match.end():end].strip()
        extension[match.group(1)] = value.replace('\\=', '=').replace('\\\\', '\\')
    return extension


class CefAdapter(DetectionAdapter):
    name = 'cef'
    version = '1.0'
    source_tool = 'cef'
    description = 'Generic ArcSight CEF line (firewall, WAF, proxy, legacy IDS)'

    def matches(self, payload: Dict[str, Any]) -> bool:
        return bool(_CEF_PREFIX.match(str(payload.get('cef') or payload.get('message') or '')))

    def parse(self, payload: Dict[str, Any]) -> Detection:
        line = str(payload.get('cef') or payload.get('message') or '').strip()
        if not _CEF_PREFIX.match(line):
            raise DetectionParseError('Not a CEF line — expected a `cef` or `message` field starting with CEF:<n>|')

        fields = _split_header(line)
        if len(fields) < _HEADER_FIELDS:
            raise DetectionParseError(
                f'Malformed CEF header — expected {_HEADER_FIELDS} pipe-separated '
                f'fields, found {len(fields)}'
            )

        _, vendor, product, _version, signature_id, name, severity_text, extension_text = fields
        extension = _parse_extension(extension_text)

        # CEF severity is 0-10, and the contract's normaliser reads anything
        # above 15 as a 0-100 scale — so an unscaled 10 would come out LOW when
        # it means the opposite. Rescaled here, where the scale is known.
        try:
            severity = normalize_severity(float(severity_text.strip()) * 10)
        except ValueError:
            severity = normalize_severity(severity_text.strip())

        # CEF has no technique field. Some products put one in a custom string
        # slot and label it; that label is the only thing that makes the value
        # readable, so an unlabelled cs1 is left alone rather than guessed at.
        techniques = ()
        if str(extension.get('cs1Label', '')).strip().lower() in ('technique', 'mitre', 'mitre attack', 'mitreattack'):
            techniques = (extension.get('cs1'),)

        # A tool that names itself is more useful than the literal 'cef'.
        tool = (str(payload.get('source_tool') or '').strip()
                or '-'.join(part for part in (vendor.strip(), product.strip()) if part)
                or self.source_tool)

        return self.build(
            payload,
            source_tool=tool.lower().replace(' ', '-'),
            detected_at=parse_timestamp(
                extension.get('rt') or extension.get('start') or extension.get('end')
                or payload.get('timestamp')
            ),
            rule_id=signature_id.strip(),
            rule_name=name.strip() or f'CEF signature {signature_id.strip()}',
            vendor_severity=severity_text.strip(),
            severity=severity,
            techniques=techniques,
            message=extension.get('msg') or name.strip(),
            src_ip=extension.get('src') or extension.get('sourceAddress'),
            dst_ip=extension.get('dst') or extension.get('destinationAddress'),
            host=extension.get('dvchost') or extension.get('shost') or extension.get('dhost'),
            host_ip=extension.get('dvc') or extension.get('deviceAddress'),
            user=extension.get('suser') or extension.get('duser'),
            process=extension.get('sproc') or extension.get('dproc'),
            file_hash=extension.get('fileHash'),
            url=extension.get('request') or extension.get('requestUrl'),
            domain=extension.get('destinationDnsDomain') or extension.get('sourceDnsDomain'),
        )
