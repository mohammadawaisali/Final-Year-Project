"""
Enhanced Metadata Parser Module
Extracts and analyzes metadata from multiple file types
Supports: Images (EXIF), Office Documents, PDFs, and generic files
"""

from pathlib import Path
from PIL import Image
from PIL.ExifTags import TAGS
from datetime import datetime
import os
import platform
import zipfile
import xml.etree.ElementTree as ET
from forensic_intelligence import ForensicIntelligence, ForensicReporter

class MetadataParser:
    """Extracts and analyzes file metadata from multiple file types"""
    
    def __init__(self):
        """Initialize metadata parser"""
        self.results = []
        
        # Define file type categories
        self.image_extensions = ['.jpg', '.jpeg', '.png', '.tiff', '.gif', '.bmp']
        self.office_extensions = ['.docx', '.xlsx', '.pptx']
        self.pdf_extensions = ['.pdf']
    
    def get_file_system_timestamps(self, filepath):
        """
        Extract file system timestamps
        
        Args:
            filepath: Path to file
            
        Returns:
            dict: File system timestamps
        """
        try:
            stat = os.stat(filepath)
            
            timestamps = {
                'modified': datetime.fromtimestamp(stat.st_mtime),
                'accessed': datetime.fromtimestamp(stat.st_atime),
            }
            
            # Birth time (creation) - platform dependent
            if platform.system() == 'Darwin':  # macOS
                timestamps['created'] = datetime.fromtimestamp(stat.st_birthtime)
            elif platform.system() == 'Windows':
                timestamps['created'] = datetime.fromtimestamp(stat.st_ctime)
            else:  # Linux
                timestamps['created'] = datetime.fromtimestamp(stat.st_ctime)
            
            return timestamps
            
        except Exception as e:
            return {'error': str(e)}
    
    # ===== IMAGE METADATA (EXIF) =====
    
    def extract_exif(self, filepath):
        """Extract EXIF data from image file"""
        try:
            image = Image.open(filepath)
            exif_data = {}
            
            exif = image.getexif()
            
            if exif is None or len(exif) == 0:
                return {'status': 'no_exif'}
            
            for tag_id, value in exif.items():
                tag_name = TAGS.get(tag_id, tag_id)
                
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8', errors='ignore')
                    except:
                        value = str(value)
                
                exif_data[tag_name] = value
            
            return exif_data if exif_data else {'status': 'no_exif'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_image_metadata(self, filepath):
        """Analyze image file metadata"""
        exif_data = self.extract_exif(filepath)
        
        metadata = {
            'Make': exif_data.get('Make', 'N/A'),
            'Model': exif_data.get('Model', 'N/A'),
            'Software': exif_data.get('Software', 'N/A'),
            'DateTime': exif_data.get('DateTime', 'N/A'),
            'GPSInfo': exif_data.get('GPSInfo', 'N/A')
        }
        
        suspicious_indicators = []
        
        if exif_data.get('status') == 'no_exif':
            suspicious_indicators.append("No EXIF data (possibly stripped)")
        
        if metadata['Make'] == 'N/A' and metadata['Model'] == 'N/A':
            suspicious_indicators.append("No camera information")
        
        if metadata['DateTime'] == 'N/A':
            suspicious_indicators.append("No EXIF timestamp data")
        
        if metadata['GPSInfo'] == 'N/A':
            # GPS missing is normal for many photos
            pass
        
        return {
            'has_metadata': exif_data.get('status') != 'no_exif',
            'metadata': metadata,
            'exif_fields_count': len(exif_data) if isinstance(exif_data, dict) and 'status' not in exif_data else 0,
            'suspicious_indicators': suspicious_indicators
        }
    
    # ===== OFFICE DOCUMENT METADATA (DOCX, XLSX, PPTX) =====
    
    def extract_office_metadata(self, filepath):
        """
        Extract metadata from Office documents (DOCX, XLSX, PPTX)
        Office files are ZIP archives containing XML metadata
        """
        try:
            metadata = {}
            
            # Office files are ZIP archives
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                # Core properties are in docProps/core.xml
                if 'docProps/core.xml' in zip_ref.namelist():
                    core_xml = zip_ref.read('docProps/core.xml')
                    root = ET.fromstring(core_xml)
                    
                    # Define namespaces
                    ns = {
                        'dc': 'http://purl.org/dc/elements/1.1/',
                        'dcterms': 'http://purl.org/dc/terms/',
                        'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties'
                    }
                    
                    # Extract common properties
                    metadata['Title'] = self._get_xml_text(root, './/dc:title', ns)
                    metadata['Creator'] = self._get_xml_text(root, './/dc:creator', ns)
                    metadata['LastModifiedBy'] = self._get_xml_text(root, './/cp:lastModifiedBy', ns)
                    metadata['Created'] = self._get_xml_text(root, './/dcterms:created', ns)
                    metadata['Modified'] = self._get_xml_text(root, './/dcterms:modified', ns)
                    metadata['Subject'] = self._get_xml_text(root, './/dc:subject', ns)
                    metadata['Keywords'] = self._get_xml_text(root, './/cp:keywords', ns)
                    metadata['Description'] = self._get_xml_text(root, './/dc:description', ns)
                    metadata['Revision'] = self._get_xml_text(root, './/cp:revision', ns)
                
                # App properties in docProps/app.xml
                if 'docProps/app.xml' in zip_ref.namelist():
                    app_xml = zip_ref.read('docProps/app.xml')
                    app_root = ET.fromstring(app_xml)
                    
                    app_ns = {'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'}
                    
                    metadata['Application'] = self._get_xml_text(app_root, './/ep:Application', app_ns)
                    metadata['Company'] = self._get_xml_text(app_root, './/ep:Company', app_ns)
                    metadata['TotalEditTime'] = self._get_xml_text(app_root, './/ep:TotalTime', app_ns)
            
            return metadata if metadata else {'status': 'no_metadata'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _get_xml_text(self, root, path, namespaces):
        """Helper to safely extract XML text"""
        try:
            element = root.find(path, namespaces)
            return element.text if element is not None and element.text else 'N/A'
        except:
            return 'N/A'
    
    def analyze_office_metadata(self, filepath):
        """Analyze Office document metadata"""
        office_data = self.extract_office_metadata(filepath)
        
        if 'error' in office_data:
            return {
                'has_metadata': False,
                'metadata': {},
                'suspicious_indicators': [f"Error reading metadata: {office_data['error']}"]
            }
        
        metadata = {
            'Author': office_data.get('Creator', 'N/A'),
            'LastModifiedBy': office_data.get('LastModifiedBy', 'N/A'),
            'Created': office_data.get('Created', 'N/A'),
            'Modified': office_data.get('Modified', 'N/A'),
            'Application': office_data.get('Application', 'N/A'),
            'Company': office_data.get('Company', 'N/A'),
            'Title': office_data.get('Title', 'N/A'),
            'Revision': office_data.get('Revision', 'N/A')
        }
        
        suspicious_indicators = []
        
        if office_data.get('status') == 'no_metadata':
            suspicious_indicators.append("No document metadata found")
        
        if metadata['Author'] == 'N/A':
            suspicious_indicators.append("No author information")
        
        if metadata['Created'] == 'N/A' and metadata['Modified'] == 'N/A':
            suspicious_indicators.append("No document timestamps")
        
        if metadata['LastModifiedBy'] != 'N/A' and metadata['Author'] != 'N/A':
            if metadata['LastModifiedBy'] != metadata['Author']:
                suspicious_indicators.append(
                    f"Document modified by different user: {metadata['LastModifiedBy']}"
                )
        
        # Check for suspicious application names
        if metadata['Application'] not in ['N/A', 'Microsoft Office Word', 'Microsoft Excel', 
                                           'Microsoft PowerPoint', 'LibreOffice', 'Pages', 'Numbers', 'Keynote']:
            if metadata['Application'] != 'N/A':
                suspicious_indicators.append(
                    f"Unusual application: {metadata['Application']}"
                )
        
        return {
            'has_metadata': office_data.get('status') != 'no_metadata',
            'metadata': metadata,
            'doc_fields_count': len([v for v in metadata.values() if v != 'N/A']),
            'suspicious_indicators': suspicious_indicators
        }
    
    # ===== PDF METADATA =====
    
    def extract_pdf_metadata(self, filepath):
        """Extract metadata from PDF files"""
        try:
            import PyPDF2
            
            with open(filepath, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                metadata = pdf_reader.metadata
                
                if metadata:
                    return {
                        'Title': metadata.get('/Title', 'N/A'),
                        'Author': metadata.get('/Author', 'N/A'),
                        'Creator': metadata.get('/Creator', 'N/A'),
                        'Producer': metadata.get('/Producer', 'N/A'),
                        'CreationDate': metadata.get('/CreationDate', 'N/A'),
                        'ModDate': metadata.get('/ModDate', 'N/A'),
                        'Subject': metadata.get('/Subject', 'N/A')
                    }
                else:
                    return {'status': 'no_metadata'}
                    
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_pdf_metadata(self, filepath):
        """Analyze PDF metadata"""
        pdf_data = self.extract_pdf_metadata(filepath)
        
        if 'error' in pdf_data:
            return {
                'has_metadata': False,
                'metadata': {},
                'suspicious_indicators': [f"Error reading PDF metadata: {pdf_data['error']}"]
            }
        
        metadata = {
            'Title': pdf_data.get('Title', 'N/A'),
            'Author': pdf_data.get('Author', 'N/A'),
            'Creator': pdf_data.get('Creator', 'N/A'),
            'Producer': pdf_data.get('Producer', 'N/A'),
            'CreationDate': pdf_data.get('CreationDate', 'N/A'),
            'ModDate': pdf_data.get('ModDate', 'N/A')
        }
        
        suspicious_indicators = []
        
        if pdf_data.get('status') == 'no_metadata':
            suspicious_indicators.append("No PDF metadata found")
        
        if metadata['Author'] == 'N/A':
            suspicious_indicators.append("No author information")
        
        if metadata['CreationDate'] == 'N/A':
            suspicious_indicators.append("No creation timestamp")
        
        return {
            'has_metadata': pdf_data.get('status') != 'no_metadata',
            'metadata': metadata,
            'pdf_fields_count': len([v for v in metadata.values() if v != 'N/A']),
            'suspicious_indicators': suspicious_indicators
        }
    
    # ===== TIMESTAMP ANALYSIS (ALL FILES) =====
    
    def analyze_timestamps(self, file_path, file_type_metadata=None):
        """
        Analyze file system timestamps and compare with embedded metadata
        """
        fs_timestamps = self.get_file_system_timestamps(file_path)
        anomalies = []
        
        if 'error' not in fs_timestamps:
            # Check file system timestamp consistency
            if fs_timestamps['created'] > fs_timestamps['modified']:
                anomalies.append(
                    "File System: Created timestamp newer than modified (impossible)"
                )
            
            # Check for future timestamps
            now = datetime.now()
            if fs_timestamps['modified'] > now:
                anomalies.append("File System: Modified timestamp in the future")
            
            if fs_timestamps['created'] > now:
                anomalies.append("File System: Created timestamp in the future")
            
            # Compare with embedded metadata timestamps if available
            if file_type_metadata and 'metadata' in file_type_metadata:
                meta = file_type_metadata['metadata']
                
                # With this, covering all three file types:
                embedded_ts_raw = (
                    meta.get('Modified')       # Office documents
                    or meta.get('ModDate')     # PDFs
                    or meta.get('DateTime')    # Images (EXIF)
                )
                if embedded_ts_raw and embedded_ts_raw != 'N/A':
                    try:
                        # Normalise the three different date formats
                        raw = embedded_ts_raw.strip()
                        if raw.startswith('D:'):
                            # PDF format: D:20241218141249Z00'00'
                            raw = raw[2:16]
                            doc_modified = datetime.strptime(raw, '%Y%m%d%H%M%S')
                        elif 'T' in raw:
                            # ISO format: 2013-12-23T23:15:00Z  (Office)
                            doc_modified = datetime.fromisoformat(
                                raw.replace('Z', '+00:00')
                            ).replace(tzinfo=None)
                        else:
                            # EXIF format: 2024:12:18 14:12:49
                            doc_modified = datetime.strptime(raw, '%Y:%m:%d %H:%M:%S')

                        time_diff = abs(
                            (doc_modified - fs_timestamps['modified']).total_seconds()
                        )
                        if time_diff > 86400:
                            anomalies.append(
                                f"Document metadata timestamp differs from file system "
                                f"by {int(time_diff / 86400)} days"
                            )
                    except:
                        pass
        
        return {
            'fs_timestamps': fs_timestamps if 'error' not in fs_timestamps else {},
            'anomalies': anomalies
        }
    
    # ===== MAIN ANALYSIS FUNCTION =====
    
    def analyze_file(self, filepath):
        """
        Analyze metadata of any file type
        
        Args:
            filepath: Path to file
            
        Returns:
            dict: Analysis results
        """
        try:
            file_path = Path(filepath)
            
            if not file_path.exists():
                return {
                    'filename': str(filepath),
                    'status': 'error',
                    'message': 'File not found'
                }
            
            file_ext = file_path.suffix.lower()
            file_type = 'unknown'
            type_specific_data = None
            
            # Route to appropriate parser based on file type
            if file_ext in self.image_extensions:
                file_type = 'image'
                type_specific_data = self.analyze_image_metadata(file_path)
                
            elif file_ext in self.office_extensions:
                file_type = 'office_document'
                type_specific_data = self.analyze_office_metadata(file_path)
                
            elif file_ext in self.pdf_extensions:
                file_type = 'pdf'
                type_specific_data = self.analyze_pdf_metadata(file_path)
                
            else:
                # For unknown file types, just analyze file system metadata
                file_type = 'generic'
                type_specific_data = {
                    'has_metadata': False,
                    'metadata': {},
                    'suspicious_indicators': []
                }
            
            # Analyze timestamps for all files
            timestamp_analysis = self.analyze_timestamps(file_path, type_specific_data)
            
            # Combine suspicious indicators
            all_suspicious_indicators = []
            if type_specific_data:
                all_suspicious_indicators.extend(type_specific_data.get('suspicious_indicators', []))
            all_suspicious_indicators.extend(timestamp_analysis.get('anomalies', []))
            
            # Build result
            result = {
                'filename': file_path.name,
                'filepath': str(file_path),
                'file_type': file_type,
                'has_metadata': type_specific_data.get('has_metadata', False) if type_specific_data else False,
                'metadata': type_specific_data.get('metadata', {}) if type_specific_data else {},
                'fs_timestamps': timestamp_analysis.get('fs_timestamps', {}),
                'suspicious_indicators': all_suspicious_indicators,
                'status': 'suspicious' if all_suspicious_indicators else 'normal',
                'metadata_fields_count': type_specific_data.get('exif_fields_count', 
                                        type_specific_data.get('doc_fields_count',
                                        type_specific_data.get('pdf_fields_count', 0))) if type_specific_data else 0
            }
            
            self.results.append(result)
            return result
            
        except Exception as e:
            return {
                'filename': str(filepath),
                'status': 'error',
                'message': str(e)
            }
    
    def analyze_directory(self, directory_path):
        """Analyze all files in a directory"""
        directory = Path(directory_path)
        
        if not directory.exists() or not directory.is_dir():
            print(f"Error: {directory_path} is not a valid directory")
            return []
        
        # Get ALL files (not just images)
        files = [f for f in directory.rglob('*') if f.is_file()]
        
        # Filter out system files
        files = [f for f in files if not f.name.startswith('.')]
        
        print(f"\nAnalyzing metadata for {len(files)} files...")
        
        for file_path in files:
            self.analyze_file(file_path)
        
        return self.results
    
    def get_suspicious_files(self):
        """Get files with metadata anomalies"""
        return [r for r in self.results if r.get('status') == 'suspicious']
    
    def print_report(self):
        """Print formatted metadata analysis report with forensic intelligence"""
        print("\n" + "="*70)
        print("METADATA ANALYSIS REPORT - INTELLIGENT FORENSIC ASSESSMENT")
        print("="*70)
        
        # Initialize intelligence engine
        intelligence = ForensicIntelligence()
        reporter = ForensicReporter()
        
        total_files = len(self.results)
        files_with_metadata = len([r for r in self.results if r.get('has_metadata')])
        
        # Intelligent risk assessment
        risk_distribution = {'normal': 0, 'low_risk': 0, 'suspicious': 0, 'highly_suspicious': 0}
        
        # Re-analyze with intelligence
        intelligent_results = []
        for result in self.results:
            if result.get('status') == 'skipped':
                continue
            
            # Apply forensic intelligence
            analysis = intelligence.analyze_anomalies(
                result.get('suspicious_indicators', []),
                result.get('metadata', {}),
                result.get('file_type', 'unknown')
            )
            
            result['intelligent_analysis'] = analysis
            risk_distribution[analysis['risk_level']] += 1
            intelligent_results.append(result)
        
        # Summary
        print(f"\nTotal Files Analyzed: {total_files}")
        print(f"Files with Metadata: {files_with_metadata}")
        
        print(f"\nRisk Distribution:")
        print(f"   Normal: {risk_distribution['normal']}")
        print(f"    Low Risk: {risk_distribution['low_risk']}")
        print(f"    Suspicious: {risk_distribution['suspicious']}")
        print(f"   Highly Suspicious: {risk_distribution['highly_suspicious']}")
        
        # Detailed findings
        print("\n" + "-"*70)
        print("INTELLIGENT FORENSIC ANALYSIS:")
        print("-"*70)
        
        # Sort by risk score (highest first)
        intelligent_results.sort(
            key=lambda x: x.get('intelligent_analysis', {}).get('risk_score', 0),
            reverse=True
        )
        
        for result in intelligent_results:
            analysis = result.get('intelligent_analysis', {})
            report_text = reporter.format_intelligent_findings(
                analysis, result['filename']
            )
            print(report_text)
        
        print("\n" + "="*70)