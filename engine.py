import hashlib
import io
import gc
import logging
from typing import Dict, Any, Tuple, Optional, List
import pypdf

# Set up backend logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RedPurgePDF_Engine")

def calculate_sha256(file_bytes: bytes) -> str:
    """
    Computes the SHA-256 hash value of binary file bytes to establish the chain of custody.
    """
    if not file_bytes:
        return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # Hash of empty bytes
    sha256_hash = hashlib.sha256()
    # Process in chunks of 64KB to be extremely memory efficient
    for i in range(0, len(file_bytes), 65536):
        sha256_hash.update(file_bytes[i:i+65536])
    return sha256_hash.hexdigest()

def extract_metadata(file_bytes: bytes, password: Optional[str] = None) -> Dict[str, Any]:
    """
    Parses a PDF from bytes, handles decryption resiliently, and extracts forensic information dictionary keys.
    """
    result = {
        "size_bytes": len(file_bytes),
        "is_encrypted": False,
        "is_decrypted": True,
        "num_pages": 0,
        "author": "N/A",
        "creator": "N/A",
        "producer": "N/A",
        "creation_date": "N/A",
        "mod_date": "N/A",
        "title": "N/A",
        "subject": "N/A",
        "has_xmp": False,
        "has_piece_info": False,
        "error": None
    }

    try:
        # Wrap bytes in BytesIO buffer for in-memory parsing
        file_stream = io.BytesIO(file_bytes)
        reader = pypdf.PdfReader(file_stream)

        # Check for encryption status
        if reader.is_encrypted:
            result["is_encrypted"] = True
            result["is_decrypted"] = False
            
            if password is not None:
                try:
                    decryption_success = reader.decrypt(password)
                    if decryption_success > 0:
                        result["is_decrypted"] = True
                    else:
                        result["error"] = "Authentication failed. Incorrect password provided."
                        return result
                except Exception as decrypt_err:
                    result["error"] = f"Decryption error: {str(decrypt_err)}"
                    return result
            else:
                result["error"] = "File is encrypted. A decryption password is required to continue."
                return result

        # Record page count
        result["num_pages"] = len(reader.pages)

        # Extract standard /Info dictionary metadata
        meta = reader.metadata
        if meta:
            result["author"] = meta.author if meta.author else "Empty"
            result["creator"] = meta.creator if meta.creator else "Empty"
            result["producer"] = meta.producer if meta.producer else "Empty"
            result["creation_date"] = meta.creation_date if meta.creation_date else "Empty"
            result["mod_date"] = meta.modification_date if meta.modification_date else "Empty"
            result["title"] = meta.title if meta.title else "Empty"
            result["subject"] = meta.subject if meta.subject else "Empty"

        # Check for XMP Metadata stream (catalog-level)
        try:
            if reader.xmp_metadata is not None:
                result["has_xmp"] = True
        except Exception:
            pass

        # Check for PieceInfo / private document level metadata
        catalog = None
        if hasattr(reader, "root_object"):
            catalog = reader.root_object
        elif hasattr(reader, "_root_object"):
            catalog = reader._root_object

        if catalog and "/PieceInfo" in catalog:
            result["has_piece_info"] = True

    except pypdf.errors.PdfReadError as pdf_err:
        result["error"] = f"Structural PDF Parsing Error: {str(pdf_err)}"
    except Exception as e:
        result["error"] = f"Forensic Parsing Failure: {str(e)}"
    
    return result

def sanitize_pdf(file_bytes: bytes, password: Optional[str] = None) -> Tuple[Optional[bytes], Dict[str, Any]]:
    """
    Deep metadata sanitizer that purges `/Info` dictionaries, XMP metadata streams, and
    performs deep page-level scrubbing (removing `/PieceInfo`, `/Metadata`, `/StructParents`).
    Prevents incremental revisions by fully compiling a brand new PDF stream.
    """
    stats = {
        "status": "Failed",
        "metadata_fields_purged": 0,
        "page_elements_scrubbed": 0,
        "xmp_purged": False,
        "incremental_prevented": True,
        "neutralized_log": {
            "/Author": (False, "N/A"),
            "/Creator": (False, "N/A"),
            "/Producer": (False, "N/A"),
            "/CreationDate": (False, "N/A"),
            "/ModDate": (False, "N/A"),
            "/XMP Metadata": (False, "N/A"),
            "/PieceInfo": (False, "N/A")
        },
        "error": None
    }

    try:
        file_stream = io.BytesIO(file_bytes)
        reader = pypdf.PdfReader(file_stream)

        # Decrypt if necessary
        if reader.is_encrypted:
            if not password:
                stats["error"] = "Authentication required for sanitization."
                return None, stats
            reader.decrypt(password)

        # Populate pre-purging status
        meta = reader.metadata
        if meta:
            if meta.author:
                stats["neutralized_log"]["/Author"] = (True, str(meta.author))
            if meta.creator:
                stats["neutralized_log"]["/Creator"] = (True, str(meta.creator))
            if meta.producer:
                stats["neutralized_log"]["/Producer"] = (True, str(meta.producer))
            if meta.creation_date:
                stats["neutralized_log"]["/CreationDate"] = (True, str(meta.creation_date))
            if meta.modification_date:
                stats["neutralized_log"]["/ModDate"] = (True, str(meta.modification_date))

        try:
            if reader.xmp_metadata is not None:
                stats["neutralized_log"]["/XMP Metadata"] = (True, "XML Metadata Stream")
        except Exception:
            pass

        # Check Catalog /PieceInfo
        catalog_in = None
        if hasattr(reader, "root_object"):
            catalog_in = reader.root_object
        elif hasattr(reader, "_root_object"):
            catalog_in = reader._root_object

        if catalog_in and "/PieceInfo" in catalog_in:
            stats["neutralized_log"]["/PieceInfo"] = (True, "Catalog-level PieceInfo")

        # Check Page-level /PieceInfo
        for page in reader.pages:
            page_obj = page.get_object()
            if "/PieceInfo" in page_obj:
                stats["neutralized_log"]["/PieceInfo"] = (True, "Page-level PieceInfo")
                break

        writer = pypdf.PdfWriter()

        # Target metadata markers to scrub
        info_keys_to_clear = [
            "/Author", "/Creator", "/Producer", "/CreationDate", 
            "/ModDate", "/Title", "/Subject", "/Keywords"
        ]
        
        # Count existing non-empty metadata points for statistics
        if meta:
            for val in [meta.author, meta.creator, meta.producer, meta.creation_date, meta.modification_date, meta.title, meta.subject]:
                if val:
                    stats["metadata_fields_purged"] += 1

        # Deep page-level metadata cleansing
        for i, page in enumerate(reader.pages):
            # Fetch underlying page dictionary object
            page_obj = page.get_object()
            
            # Scan and purge tracking mechanisms at page level
            page_scrubbed_keys = ["/PieceInfo", "/Metadata", "/StructParents"]
            for key in page_scrubbed_keys:
                if key in page_obj:
                    page_obj.pop(key)
                    stats["page_elements_scrubbed"] += 1
            
            # Safely process and cleanse page level annotations if present
            if "/Annots" in page_obj:
                try:
                    annots = page_obj["/Annots"]
                    # If indirect or direct list, scan annotations for PieceInfo or metadata
                    if isinstance(annots, pypdf.generic.ArrayObject):
                        for annot_ref in annots:
                            annot_obj = annot_ref.get_object()
                            if isinstance(annot_obj, pypdf.generic.DictionaryObject):
                                for key in page_scrubbed_keys:
                                    if key in annot_obj:
                                        annot_obj.pop(key)
                                        stats["page_elements_scrubbed"] += 1
                except Exception:
                    pass  # Pass if parsing annotations fails to avoid crashing
            
            # Copy cleansed page to the fresh writer
            writer.add_page(page)

        # Build clean blank metadata dictionary, overriding any Info markers with empty fields
        writer.add_metadata({
            "/Author": "",
            "/Creator": "",
            "/Producer": "",
            "/CreationDate": "",
            "/ModDate": "",
            "/Title": "",
            "/Subject": ""
        })

        # Strip catalog-level XMP Metadata stream & PieceInfo
        catalog = None
        if hasattr(writer, "root_object"):
            catalog = writer.root_object
        elif hasattr(writer, "_root_object"):
            catalog = writer._root_object

        if catalog:
            if "/Metadata" in catalog:
                catalog.pop("/Metadata")
                stats["xmp_purged"] = True
            if "/PieceInfo" in catalog:
                catalog.pop("/PieceInfo")
                stats["page_elements_scrubbed"] += 1
            if "/StructTreeRoot" in catalog:
                catalog.pop("/StructTreeRoot")
                stats["page_elements_scrubbed"] += 1

        # Compile final PDF into RAM buffer, guaranteeing complete revision overwrite
        output_buffer = io.BytesIO()
        writer.write(output_buffer)
        cleaned_bytes = output_buffer.getvalue()
        
        output_buffer.close()
        file_stream.close()

        stats["status"] = "Success"
        return cleaned_bytes, stats

    except Exception as e:
        stats["error"] = f"Sanitization processing crashed: {str(e)}"
        return None, stats

def validate_sanitized_pdf(original_hash: str, cleaned_bytes: bytes) -> Dict[str, Any]:
    """
    Self-validation and cross-validation compiler.
    Reads back the cleaned PDF stream with a fresh parser, verifying visual structure and 100% metadata purge.
    """
    validation = {
        "is_valid_structure": False,
        "sha256_match": False,
        "metadata_fully_purged": False,
        "remaining_fields": [],
        "pages_intact": False,
        "errors": []
    }

    try:
        cleaned_hash = calculate_sha256(cleaned_bytes)
        validation["sha256_match"] = (original_hash == cleaned_hash)

        # Audit readback
        audit_stream = io.BytesIO(cleaned_bytes)
        reader = pypdf.PdfReader(audit_stream)

        # Check visual structure (can read pages)
        num_pages = len(reader.pages)
        if num_pages > 0:
            validation["is_valid_structure"] = True
            validation["pages_intact"] = True
        
        # Verify /Info dictionary is empty or purged
        meta = reader.metadata
        fields_found = []
        if meta:
            for key in ["author", "creator", "producer", "creation_date", "modification_date", "title", "subject"]:
                val = getattr(meta, key, None)
                if val and val != "Empty" and val != "":
                    fields_found.append(f"/Info/{key.capitalize()}: {val}")
        
        # Verify catalog structure
        catalog = None
        if hasattr(reader, "root_object"):
            catalog = reader.root_object
        elif hasattr(reader, "_root_object"):
            catalog = reader._root_object

        if catalog:
            if "/Metadata" in catalog:
                fields_found.append("Catalog/Metadata (XMP Stream)")
            if "/PieceInfo" in catalog:
                fields_found.append("Catalog/PieceInfo")
            if "/StructTreeRoot" in catalog:
                fields_found.append("Catalog/StructTreeRoot")

        # Verify page structure
        for idx, page in enumerate(reader.pages):
            page_obj = page.get_object()
            if "/PieceInfo" in page_obj:
                fields_found.append(f"Page {idx+1}/PieceInfo")
            if "/Metadata" in page_obj:
                fields_found.append(f"Page {idx+1}/Metadata")
            if "/StructParents" in page_obj:
                fields_found.append(f"Page {idx+1}/StructParents")

        if len(fields_found) == 0:
            validation["metadata_fully_purged"] = True
        else:
            validation["remaining_fields"] = fields_found

        audit_stream.close()

    except Exception as e:
        validation["errors"].append(f"Verification parser check failed: {str(e)}")

    return validation
