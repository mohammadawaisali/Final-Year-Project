"""
Hash Verification Module — VirusTotal Integration
Calculates cryptographic hashes for file integrity verification
and queries the VirusTotal API to flag known malicious files.

VirusTotal Free Tier Limits:
  - 4 requests per minute
  - 500 requests per day
  - Rate limiting enforced automatically via _vt_rate_limit()

API Key Setup:
  Set the environment variable before running:
      export VIRUSTOTAL_API_KEY="your_key_here"
  Never hardcode the key directly in this file.
"""

import os
import time
import hashlib
import requests
from pathlib import Path
from collections import defaultdict
from datetime import datetime


# ── VirusTotal API constants ──────────────────────────────────────────────────
VT_API_BASE        = "https://www.virustotal.com/api/v3/files"
VT_MIN_INTERVAL    = 15.0      # seconds between calls (enforces 4 req/min limit)
VT_REQUEST_TIMEOUT = 15        # seconds before giving up on a request


class HashVerifier:
    """
    Calculates MD5, SHA-1, and SHA-256 hashes for files,
    detects duplicates, and optionally queries the VirusTotal
    API to check each hash against known malware databases.
    """

    def __init__(self):
        """Initialise hash verifier and load VirusTotal API key."""
        self.results       = []
        self.hash_database = defaultdict(list)

        # Load API key from environment — never from hardcoded string
        self.vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        if not self.vt_api_key:
            print("[WARN] VIRUSTOTAL_API_KEY not set. "
                  "VirusTotal checks will be skipped.")

        # Tracks the timestamp of the last VT call for rate limiting
        self._last_vt_call = 0.0

        # Simple in-session cache: sha256 → vt result dict
        # Avoids spending API quota on files already checked this run
        self._vt_cache = {}

    # =========================================================================
    # HASH COMPUTATION
    # =========================================================================

    def calculate_hashes(self, filepath, algorithms=None):
        """
        Calculate multiple hash algorithms for a file in a single pass.

        Args:
            filepath  : Path to the file (str or Path)
            algorithms: List of algorithm names. Defaults to
                        ['md5', 'sha1', 'sha256']

        Returns:
            dict: { 'md5': '...', 'sha1': '...', 'sha256': '...' }
                  or { 'error': '<message>' } on failure
        """
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256']

        try:
            hash_objects = {alg: hashlib.new(alg) for alg in algorithms}

            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    for h in hash_objects.values():
                        h.update(chunk)

            return {alg: hash_objects[alg].hexdigest() for alg in algorithms}

        except PermissionError:
            return {'error': 'Permission denied — cannot read file'}
        except FileNotFoundError:
            return {'error': 'File not found'}
        except Exception as e:
            return {'error': str(e)}

    # =========================================================================
    # VIRUSTOTAL API
    # =========================================================================

    def _vt_rate_limit(self):
        """
        Block until at least VT_MIN_INTERVAL seconds have passed
        since the last VirusTotal request. Ensures compliance with
        the free-tier limit of 4 requests per minute.
        """
        elapsed = time.time() - self._last_vt_call
        if elapsed < VT_MIN_INTERVAL:
            wait = VT_MIN_INTERVAL - elapsed
            print(f"      [VT] Rate limit — waiting {wait:.1f}s…")
            time.sleep(wait)
        self._last_vt_call = time.time()

    def _query_virustotal(self, sha256: str) -> dict:
        """
        Query the VirusTotal v3 API for a SHA-256 hash.

        The SHA-256 is used (not MD5/SHA-1) because it is the most
        specific identifier and least likely to produce false matches.

        Returns a standardised dict:
        {
            'vt_verdict'      : 'MALICIOUS' | 'CLEAN' | 'UNKNOWN' | 'SKIPPED' | 'ERROR',
            'vt_malicious'    : int,    # engines that flagged it
            'vt_total_engines': int,    # total engines that scanned it
            'vt_detection_ratio': str,  # e.g. "3/72"
            'vt_threat_names' : list,   # AV detection names (up to 5)
            'vt_last_analysis': str,    # ISO timestamp of last VT scan
            'vt_link'         : str,    # direct URL to VT report
            'vt_status'       : str,    # raw API status for debugging
        }
        """
        # ── Skip if no API key configured ─────────────────────────────────
        if not self.vt_api_key:
            return {
                'vt_verdict':       'SKIPPED',
                'vt_status':        'no_api_key',
                'vt_malicious':     0,
                'vt_total_engines': 0,
                'vt_detection_ratio': 'N/A',
                'vt_threat_names':  [],
                'vt_last_analysis': 'N/A',
                'vt_link':          'N/A',
            }

        # ── Return cached result if already checked this session ───────────
        if sha256 in self._vt_cache:
            print(f"      [VT] Cache hit for {sha256[:16]}…")
            return self._vt_cache[sha256]

        # ── Enforce rate limit ─────────────────────────────────────────────
        self._vt_rate_limit()

        url     = f"{VT_API_BASE}/{sha256}"
        headers = {"x-apikey": self.vt_api_key}

        try:
            response = requests.get(url, headers=headers,
                                    timeout=VT_REQUEST_TIMEOUT)

            # ── Hash not in VirusTotal database ───────────────────────────
            if response.status_code == 404:
                result = {
                    'vt_verdict':         'UNKNOWN',
                    'vt_status':          'not_found',
                    'vt_malicious':       0,
                    'vt_total_engines':   0,
                    'vt_detection_ratio': 'N/A',
                    'vt_threat_names':    [],
                    'vt_last_analysis':   'N/A',
                    'vt_link':            f"https://www.virustotal.com/gui/file/{sha256}",
                }
                self._vt_cache[sha256] = result
                return result

            # ── Rate limit exceeded (shouldn't happen with our limiter) ───
            if response.status_code == 429:
                print("      [VT] Rate limit exceeded — backing off 60s…")
                time.sleep(60)
                return {
                    'vt_verdict':         'ERROR',
                    'vt_status':          'rate_limited',
                    'vt_malicious':       0,
                    'vt_total_engines':   0,
                    'vt_detection_ratio': 'N/A',
                    'vt_threat_names':    [],
                    'vt_last_analysis':   'N/A',
                    'vt_link':            'N/A',
                }

            # ── Authentication failure ─────────────────────────────────────
            if response.status_code == 401:
                print("      [VT] Invalid API key — check VIRUSTOTAL_API_KEY")
                return {
                    'vt_verdict':         'ERROR',
                    'vt_status':          'invalid_api_key',
                    'vt_malicious':       0,
                    'vt_total_engines':   0,
                    'vt_detection_ratio': 'N/A',
                    'vt_threat_names':    [],
                    'vt_last_analysis':   'N/A',
                    'vt_link':            'N/A',
                }

            response.raise_for_status()
            data = response.json()

            # ── Parse the analysis stats ───────────────────────────────────
            attributes = data['data']['attributes']
            stats      = attributes.get('last_analysis_stats', {})
            results    = attributes.get('last_analysis_results', {})

            malicious_count = stats.get('malicious',  0)
            suspicious_count= stats.get('suspicious', 0)
            total_engines   = sum(stats.values())

            # Collect the names AV engines gave to the threat
            threat_names = sorted(set(
                engine_data['result']
                for engine_data in results.values()
                if engine_data.get('category') in ('malicious', 'suspicious')
                and engine_data.get('result')
            ))[:5]    # cap at 5 to keep reports readable

            # Convert Unix timestamp to readable string
            last_ts = attributes.get('last_analysis_date', 0)
            if last_ts:
                last_analysis = datetime.utcfromtimestamp(
                    last_ts).strftime('%Y-%m-%d %H:%M UTC')
            else:
                last_analysis = 'N/A'

            # Verdict logic:
            #   ≥ 3 engines flag it → MALICIOUS  (strong consensus)
            #   1–2 engines flag it → SUSPICIOUS  (weak signal)
            #   0 engines flag it   → CLEAN
            if malicious_count >= 3:
                verdict = 'MALICIOUS'
            elif malicious_count > 0 or suspicious_count > 0:
                verdict = 'SUSPICIOUS'
            else:
                verdict = 'CLEAN'

            result = {
                'vt_verdict':           verdict,
                'vt_status':            'found',
                'vt_malicious':         malicious_count,
                'vt_suspicious':        suspicious_count,
                'vt_total_engines':     total_engines,
                'vt_detection_ratio':   f"{malicious_count}/{total_engines}",
                'vt_threat_names':      threat_names,
                'vt_last_analysis':     last_analysis,
                'vt_link':              f"https://www.virustotal.com/gui/file/{sha256}",
            }

            self._vt_cache[sha256] = result
            return result

        except requests.exceptions.Timeout:
            print(f"      [VT] Request timed out for {sha256[:16]}…")
            return {
                'vt_verdict':         'ERROR',
                'vt_status':          'timeout',
                'vt_malicious':       0,
                'vt_total_engines':   0,
                'vt_detection_ratio': 'N/A',
                'vt_threat_names':    [],
                'vt_last_analysis':   'N/A',
                'vt_link':            'N/A',
            }
        except Exception as e:
            print(f"      [VT] Unexpected error: {e}")
            return {
                'vt_verdict':         'ERROR',
                'vt_status':          f'error: {str(e)}',
                'vt_malicious':       0,
                'vt_total_engines':   0,
                'vt_detection_ratio': 'N/A',
                'vt_threat_names':    [],
                'vt_last_analysis':   'N/A',
                'vt_link':            'N/A',
            }

    # =========================================================================
    # FILE ANALYSIS  (core public method)
    # =========================================================================

    def analyze_file(self, filepath, check_virustotal=False):
        """
        Analyse a single file: compute hashes, detect duplicates,
        and optionally query VirusTotal.

        Args:
            filepath          : Path to the file (str or Path)
            check_virustotal  : If True, query VT for the SHA-256 hash.
                                Defaults to False so existing callers that
                                do not pass this argument are unaffected.

        Returns:
            dict with keys:
                filename, filepath, md5, sha1, sha256,
                size_bytes, status,
                vt_verdict, vt_detection_ratio, vt_threat_names,
                vt_link, vt_last_analysis  (all present; 'SKIPPED' when
                                             check_virustotal=False)
        """
        try:
            file_path = Path(filepath)

            if not file_path.exists():
                return {
                    'filename': str(filepath),
                    'status':   'error',
                    'message':  'File not found',
                }

            # ── Compute hashes ─────────────────────────────────────────────
            hashes = self.calculate_hashes(file_path)

            if 'error' in hashes:
                return {
                    'filename': file_path.name,
                    'status':   'error',
                    'message':  hashes['error'],
                }

            # ── Build base result ──────────────────────────────────────────
            result = {
                'filename':   file_path.name,
                'filepath':   str(file_path),
                'md5':        hashes.get('md5',    'N/A'),
                'sha1':       hashes.get('sha1',   'N/A'),
                'sha256':     hashes.get('sha256', 'N/A'),
                'size_bytes': file_path.stat().st_size,
                'status':     'success',

                # Default VT fields (populated below if check_virustotal=True)
                'vt_verdict':         'SKIPPED',
                'vt_status':          'not_checked',
                'vt_malicious':       0,
                'vt_total_engines':   0,
                'vt_detection_ratio': 'N/A',
                'vt_threat_names':    [],
                'vt_last_analysis':   'N/A',
                'vt_link':            'N/A',
            }

            # ── Optional VirusTotal check ──────────────────────────────────
            if check_virustotal and hashes.get('sha256'):
                print(f"   [VT] Checking {file_path.name}…")
                vt_result = self._query_virustotal(hashes['sha256'])
                result.update(vt_result)   # merges all vt_* keys into result

                # Log the verdict immediately so the console stays informative
                verdict = vt_result.get('vt_verdict', 'UNKNOWN')
                ratio   = vt_result.get('vt_detection_ratio', 'N/A')
                if verdict == 'MALICIOUS':
                    print(f"      ⚠  MALICIOUS  [{ratio}]  "
                          f"{', '.join(vt_result.get('vt_threat_names', []))}")
                elif verdict == 'SUSPICIOUS':
                    print(f"      ⚠  SUSPICIOUS [{ratio}]")
                elif verdict == 'CLEAN':
                    print(f"      ✓  CLEAN      [{ratio}]")
                else:
                    print(f"      —  {verdict}")

            # ── Duplicate detection (unchanged from original) ──────────────
            self.results.append(result)
            md5_hash = hashes.get('md5')
            if md5_hash:
                self.hash_database[md5_hash].append(result)

            return result

        except Exception as e:
            return {
                'filename': str(filepath),
                'status':   'error',
                'message':  str(e),
            }

    # =========================================================================
    # DIRECTORY ANALYSIS
    # =========================================================================

    def analyze_directory(self, directory_path, check_virustotal=False):
        """
        Analyse all files in a directory.

        Args:
            directory_path   : Path to the directory (str or Path)
            check_virustotal : Forward to analyze_file() for each file.
                               Warning: with 500 files and a 15s interval
                               this will take ~2 hours on the free tier.
                               Use selectively or upgrade to a paid key.

        Returns:
            list: One result dict per file
        """
        directory = Path(directory_path)

        if not directory.exists() or not directory.is_dir():
            print(f"Error: {directory_path} is not a valid directory")
            return []

        # Exclude hidden files (same behaviour as original)
        files = [f for f in directory.rglob('*')
                 if f.is_file() and not f.name.startswith('.')]

        print(f"\nCalculating hashes for {len(files)} files…")

        if check_virustotal and self.vt_api_key:
            est_minutes = len(files) * VT_MIN_INTERVAL / 60
            print(f"[VT] VirusTotal enabled — estimated time: "
                  f"~{est_minutes:.1f} minutes "
                  f"(free tier: 4 req/min)")

        for i, file_path in enumerate(files, 1):
            print(f"  [{i}/{len(files)}] {file_path.name}")
            self.analyze_file(file_path,
                              check_virustotal=check_virustotal)

        return self.results

    # =========================================================================
    # DUPLICATE DETECTION  (unchanged from original)
    # =========================================================================

    def find_duplicates(self):
        """
        Find duplicate files based on MD5 hash.

        Returns:
            dict: { md5_hash: [result_dict, ...] } for sets with > 1 file
        """
        return {h: files
                for h, files in self.hash_database.items()
                if len(files) > 1}

    # =========================================================================
    # KNOWN-HASH DATABASE  (original method — preserved intact)
    # =========================================================================

    def verify_against_database(self, known_hashes_file=None):
        """
        Verify files against a local known-hash database (CSV format).
        This supplements the VirusTotal check with an offline list.

        CSV format expected:  md5_hash,description
        Example line:         44d88612fea8a8f36de82e1278abb02f,EICAR test file

        Args:
            known_hashes_file: Path to CSV file containing known hashes

        Returns:
            list: Matched files with their descriptions
        """
        known_hashes = {}

        if known_hashes_file and Path(known_hashes_file).exists():
            with open(known_hashes_file, 'r') as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        known_hashes[parts[0].strip().lower()] = parts[1].strip()

        matches = []
        for result in self.results:
            md5_hash = result.get('md5', '').lower()
            if md5_hash in known_hashes:
                matches.append({
                    'file':        result['filename'],
                    'hash':        md5_hash,
                    'description': known_hashes[md5_hash],
                })

        return matches

    # =========================================================================
    # REPORTING
    # =========================================================================

    def print_report(self):
        """
        Print a formatted hash verification and threat intelligence report.
        Extended from the original to include VT verdicts.
        """
        print("\n" + "=" * 70)
        print("HASH VERIFICATION & THREAT INTELLIGENCE REPORT")
        print("=" * 70)

        total = len(self.results)
        print(f"\nTotal Files Analysed: {total}")

        # Count VT verdicts
        vt_malicious  = [r for r in self.results
                         if r.get('vt_verdict') == 'MALICIOUS']
        vt_suspicious = [r for r in self.results
                         if r.get('vt_verdict') == 'SUSPICIOUS']
        vt_clean      = [r for r in self.results
                         if r.get('vt_verdict') == 'CLEAN']
        vt_unknown    = [r for r in self.results
                         if r.get('vt_verdict') == 'UNKNOWN']
        vt_skipped    = [r for r in self.results
                         if r.get('vt_verdict') == 'SKIPPED']

        if total - len(vt_skipped) > 0:
            print(f"\nVirusTotal Results:")
            print(f"  ⛔  Malicious  : {len(vt_malicious)}")
            print(f"  ⚠   Suspicious : {len(vt_suspicious)}")
            print(f"  ✓   Clean      : {len(vt_clean)}")
            print(f"  ?   Unknown    : {len(vt_unknown)}")

        # ── Malicious files — always show first ────────────────────────────
        if vt_malicious:
            print("\n" + "!" * 70)
            print("MALICIOUS FILES DETECTED:")
            print("!" * 70)
            for r in vt_malicious:
                print(f"\n  ⛔  {r['filename']}")
                print(f"      SHA-256  : {r['sha256']}")
                print(f"      Engines  : {r['vt_detection_ratio']}")
                print(f"      Threats  : {', '.join(r.get('vt_threat_names', []))}")
                print(f"      VT Link  : {r.get('vt_link', 'N/A')}")

        # ── Suspicious files ───────────────────────────────────────────────
        if vt_suspicious:
            print("\n" + "-" * 70)
            print("SUSPICIOUS FILES:")
            print("-" * 70)
            for r in vt_suspicious:
                print(f"\n  ⚠   {r['filename']}")
                print(f"      SHA-256  : {r['sha256']}")
                print(f"      Engines  : {r['vt_detection_ratio']}")

        # ── All file hashes ────────────────────────────────────────────────
        print("\n" + "-" * 70)
        print("ALL FILE HASHES:")
        print("-" * 70)
        for r in self.results:
            verdict_tag = (f"  [{r.get('vt_verdict','—')}]"
                           if r.get('vt_verdict') != 'SKIPPED' else '')
            print(f"\n  📄  {r['filename']}{verdict_tag}")
            print(f"       MD5    : {r.get('md5',    'N/A')}")
            print(f"       SHA-1  : {r.get('sha1',   'N/A')}")
            print(f"       SHA-256: {r.get('sha256', 'N/A')}")
            print(f"       Size   : {r.get('size_bytes', 0):,} bytes")

        # ── Duplicates ─────────────────────────────────────────────────────
        duplicates = self.find_duplicates()
        if duplicates:
            print("\n" + "=" * 70)
            print("DUPLICATE FILES DETECTED:")
            print("=" * 70)
            for hash_value, files in duplicates.items():
                print(f"\n  🔄  Duplicate set (MD5: {hash_value[:16]}…)")
                for f in files:
                    print(f"       — {f['filename']}")
        else:
            print("\n  ✓  No duplicate files detected")

        print("\n" + "=" * 70)

    # =========================================================================
    # EXPORT  (original method — extended with new columns)
    # =========================================================================

    def export_hashes(self, output_file):
        """
        Export hashes and VT verdicts to a CSV file.

        Columns: Filename, MD5, SHA-1, SHA-256, Size,
                 VT_Verdict, VT_Ratio, VT_Threats, VT_Link

        Args:
            output_file: Path to the output CSV file
        """
        try:
            with open(output_file, 'w') as f:
                f.write("Filename,MD5,SHA-1,SHA-256,Size,"
                        "VT_Verdict,VT_Ratio,VT_Threats,VT_Link\n")
                for r in self.results:
                    threats = '; '.join(r.get('vt_threat_names', []))
                    f.write(
                        f"{r.get('filename','N/A')},"
                        f"{r.get('md5','N/A')},"
                        f"{r.get('sha1','N/A')},"
                        f"{r.get('sha256','N/A')},"
                        f"{r.get('size_bytes',0)},"
                        f"{r.get('vt_verdict','SKIPPED')},"
                        f"{r.get('vt_detection_ratio','N/A')},"
                        f"{threats},"
                        f"{r.get('vt_link','N/A')}\n"
                    )
            print(f"\n  ✓  Hashes exported to: {output_file}")
        except Exception as e:
            print(f"\n  ✗  Error exporting hashes: {e}")