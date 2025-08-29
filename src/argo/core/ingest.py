"""PDF ingest pipeline: PyMuPDF -> OCR (fallback) -> chunk -> persist (PG) -> embed (OpenAI) -> index (FAISS)."""

import hashlib
import io
import os
import shutil
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import logging

import fitz  # PyMuPDF
import psycopg
from pydantic import BaseModel

# OCR imports (optional)
try:
    import pytesseract
    from PIL import Image
    HAS_OCR = True
except ImportError:
    HAS_OCR = False

# Configure logging
logger = logging.getLogger(__name__)


class DocumentChunk(BaseModel):
    """A chunk of text extracted from a document."""
    id: str
    document_id: str
    page: int
    bbox: List[float]  # [x0, y0, x1, y1] coordinates
    text: str
    actors: List[str] = []
    techniques: List[str] = []
    cves: List[str] = []
    confidence: float = 1.0


class DocumentInfo(BaseModel):
    """Document metadata."""
    id: str
    vendor: Optional[str] = None
    title: Optional[str] = None
    published_at: Optional[str] = None  # Will be parsed as DATE in DB
    tlp: Optional[str] = None
    sha256: str
    pages: int
    namespace: str = "personal"
    ocr_pages: int = 0


def calculate_sha256(file_path: Path) -> str:
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def extract_text_from_page(page: fitz.Page) -> Tuple[str, List[Dict[str, Any]]]:
    """Extract text and text blocks with bounding boxes from a PDF page."""
    text = page.get_text()
    text_blocks = []
    
    # Get text blocks with position information
    blocks = page.get_text("dict")["blocks"]
    for block in blocks:
        if "lines" in block:  # Text block
            block_text = ""
            bbox = block["bbox"]
            for line in block["lines"]:
                for span in line["spans"]:
                    block_text += span["text"]
                block_text += "\n"
            
            if block_text.strip():
                text_blocks.append({
                    "text": block_text.strip(),
                    "bbox": bbox
                })
    
    return text, text_blocks


def extract_text_with_ocr(page: fitz.Page) -> Tuple[str, List[Dict[str, Any]]]:
    """Extract text using OCR as fallback."""
    if not HAS_OCR:
        logger.warning("OCR dependencies not available. Install with: pip install pytesseract Pillow")
        return "", []
    
    try:
        # Convert page to image
        mat = fitz.Matrix(2.0, 2.0)  # Increase resolution for better OCR
        pix = page.get_pixmap(matrix=mat)
        img_data = pix.tobytes("png")
        
        # Convert to PIL Image
        image = Image.open(io.BytesIO(img_data))
        
        # Extract text with OCR
        ocr_text = pytesseract.image_to_string(image)
        
        # For OCR, we'll use the full page bbox
        page_rect = page.rect
        bbox = [page_rect.x0, page_rect.y0, page_rect.x1, page_rect.y1]
        
        text_blocks = [{
            "text": ocr_text.strip(),
            "bbox": bbox
        }] if ocr_text.strip() else []
        
        return ocr_text, text_blocks
        
    except Exception as e:
        logger.error(f"OCR extraction failed: {e}")
        return "", []


def chunk_text(text: str, min_tokens: int = 300, max_tokens: int = 800) -> List[str]:
    """
    Simple text chunking based on token count.
    
    Args:
        text: Input text to chunk
        min_tokens: Minimum tokens per chunk
        max_tokens: Maximum tokens per chunk
    
    Returns:
        List of text chunks
    """
    # Simple token approximation: split by whitespace
    words = text.split()
    
    if len(words) <= max_tokens:
        return [text] if text.strip() else []
    
    chunks = []
    current_chunk = []
    current_length = 0
    
    for word in words:
        if current_length + 1 > max_tokens and current_length >= min_tokens:
            # Start new chunk
            chunks.append(" ".join(current_chunk))
            current_chunk = [word]
            current_length = 1
        else:
            current_chunk.append(word)
            current_length += 1
    
    # Add remaining chunk if it meets minimum length or is the last chunk
    if current_chunk and (current_length >= min_tokens or not chunks):
        chunks.append(" ".join(current_chunk))
    
    return chunks


def create_chunks_from_blocks(
    document_id: str, 
    page_num: int, 
    text_blocks: List[Dict[str, Any]],
    min_tokens: int = 300,
    max_tokens: int = 800
) -> List[DocumentChunk]:
    """Create document chunks from text blocks."""
    chunks = []
    
    for block in text_blocks:
        text = block["text"]
        bbox = block["bbox"]
        
        # Chunk the text if it's too long
        text_chunks = chunk_text(text, min_tokens, max_tokens)
        
        for text_chunk in text_chunks:
            chunk_id = str(uuid.uuid4())
            chunk = DocumentChunk(
                id=chunk_id,
                document_id=document_id,
                page=page_num,
                bbox=bbox,
                text=text_chunk
            )
            chunks.append(chunk)
    
    return chunks


def extract_document_metadata(pdf_path: Path, doc: fitz.Document) -> DocumentInfo:
    """Extract metadata from PDF document."""
    metadata = doc.metadata
    
    # Calculate SHA256
    sha256 = calculate_sha256(pdf_path)
    
    # Generate document ID based on SHA256
    doc_id = f"doc_{sha256[:16]}"
    
    # Extract basic metadata
    title = metadata.get("title") or pdf_path.stem
    vendor = metadata.get("author")
    
    return DocumentInfo(
        id=doc_id,
        vendor=vendor,
        title=title,
        sha256=sha256,
        pages=doc.page_count,
        namespace="personal"
    )


def save_to_object_store(pdf_path: Path, sha256: str, object_store_dir: Path) -> Path:
    """Save PDF to object store using SHA256 as filename."""
    object_store_dir.mkdir(exist_ok=True)
    
    # Use SHA256 as filename to avoid duplicates
    dest_path = object_store_dir / f"{sha256}.pdf"
    
    if not dest_path.exists():
        shutil.copy2(pdf_path, dest_path)
        logger.info(f"Saved PDF to object store: {dest_path}")
    else:
        logger.info(f"PDF already exists in object store: {dest_path}")
    
    return dest_path


def save_to_database(
    document_info: DocumentInfo, 
    chunks: List[DocumentChunk], 
    db_url: str
) -> None:
    """Save document and chunks to PostgreSQL database."""
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            # Insert document
            cur.execute("""
                INSERT INTO document (id, vendor, title, published_at, tlp, sha256, pages, namespace, ocr_pages)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (sha256) DO UPDATE SET
                    vendor = EXCLUDED.vendor,
                    title = EXCLUDED.title,
                    published_at = EXCLUDED.published_at,
                    tlp = EXCLUDED.tlp,
                    pages = EXCLUDED.pages,
                    namespace = EXCLUDED.namespace,
                    ocr_pages = EXCLUDED.ocr_pages
            """, (
                document_info.id,
                document_info.vendor,
                document_info.title,
                document_info.published_at,
                document_info.tlp,
                document_info.sha256,
                document_info.pages,
                document_info.namespace,
                document_info.ocr_pages
            ))
            
            # Delete existing chunks for this document (in case of re-ingestion)
            cur.execute("DELETE FROM doc_chunk WHERE document_id = %s", (document_info.id,))
            
            # Insert chunks
            for chunk in chunks:
                cur.execute("""
                    INSERT INTO doc_chunk (
                        id, document_id, page, bbox, text, actors, techniques, cves, confidence
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    chunk.id,
                    chunk.document_id,
                    chunk.page,
                    chunk.bbox,
                    chunk.text,
                    chunk.actors,
                    chunk.techniques,
                    chunk.cves,
                    chunk.confidence
                ))
        
        conn.commit()
        logger.info(f"Saved document {document_info.id} with {len(chunks)} chunks to database")


def ingest_pdf(
    pdf_path: Path,
    object_store_dir: Path,
    db_url: str,
    min_tokens: int = 300,
    max_tokens: int = 800,
    use_ocr_fallback: bool = True
) -> Tuple[DocumentInfo, List[DocumentChunk]]:
    """
    Ingest a single PDF file.
    
    Args:
        pdf_path: Path to PDF file
        object_store_dir: Directory to store PDF files
        db_url: PostgreSQL connection URL
        min_tokens: Minimum tokens per chunk
        max_tokens: Maximum tokens per chunk
        use_ocr_fallback: Whether to use OCR for pages with little text
    
    Returns:
        Tuple of document info and chunks
    """
    logger.info(f"Ingesting PDF: {pdf_path}")
    
    # Open PDF
    doc = fitz.open(pdf_path)
    
    try:
        # Extract document metadata
        document_info = extract_document_metadata(pdf_path, doc)
        
        # Save to object store
        save_to_object_store(pdf_path, document_info.sha256, object_store_dir)
        
        # Extract text and create chunks
        all_chunks = []
        ocr_pages = 0
        
        for page_num in range(doc.page_count):
            page = doc[page_num]
            
            # Try to extract text normally first
            text, text_blocks = extract_text_from_page(page)
            
            # If very little text found and OCR is available, try OCR
            if len(text.strip()) < 50 and use_ocr_fallback:
                logger.info(f"Page {page_num + 1}: Low text content, trying OCR")
                ocr_text, ocr_blocks = extract_text_with_ocr(page)
                if len(ocr_text.strip()) > len(text.strip()):
                    text, text_blocks = ocr_text, ocr_blocks
                    ocr_pages += 1
            
            # Create chunks from text blocks
            if text_blocks:
                page_chunks = create_chunks_from_blocks(
                    document_info.id, 
                    page_num + 1,  # 1-indexed page numbers
                    text_blocks, 
                    min_tokens, 
                    max_tokens
                )
                all_chunks.extend(page_chunks)
        
        # Update OCR pages count
        document_info.ocr_pages = ocr_pages
        
        # Save to database
        save_to_database(document_info, all_chunks, db_url)
        
        logger.info(f"Successfully ingested {pdf_path}: {len(all_chunks)} chunks, {ocr_pages} OCR pages")
        return document_info, all_chunks
        
    finally:
        doc.close()


def ingest_directory(
    directory_path: Path,
    object_store_dir: Path,
    db_url: str,
    min_tokens: int = 300,
    max_tokens: int = 800,
    use_ocr_fallback: bool = True
) -> List[Tuple[DocumentInfo, List[DocumentChunk]]]:
    """
    Ingest all PDF files in a directory.
    
    Args:
        directory_path: Directory containing PDF files
        object_store_dir: Directory to store PDF files
        db_url: PostgreSQL connection URL
        min_tokens: Minimum tokens per chunk
        max_tokens: Maximum tokens per chunk
        use_ocr_fallback: Whether to use OCR for pages with little text
    
    Returns:
        List of tuples containing document info and chunks for each PDF
    """
    results = []
    pdf_files = list(directory_path.glob("*.pdf"))
    
    if not pdf_files:
        logger.warning(f"No PDF files found in {directory_path}")
        return results
    
    logger.info(f"Found {len(pdf_files)} PDF files to ingest")
    
    for pdf_path in pdf_files:
        try:
            result = ingest_pdf(
                pdf_path,
                object_store_dir,
                db_url,
                min_tokens,
                max_tokens,
                use_ocr_fallback
            )
            results.append(result)
        except Exception as e:
            logger.error(f"Failed to ingest {pdf_path}: {e}")
            continue
    
    logger.info(f"Completed ingestion: {len(results)}/{len(pdf_files)} files processed")
    return results


# Embedding integration
def embed_document_chunks(chunks: List[DocumentChunk], db_url: str) -> None:
    """
    Generate embeddings for document chunks.
    
    Args:
        chunks: List of DocumentChunk objects
        db_url: PostgreSQL connection URL
    """
    from .embed import embed_chunks as embed_chunks_func
    
    # Convert DocumentChunk objects to the format expected by embed module
    chunk_dicts = [{"id": chunk.id, "text": chunk.text} for chunk in chunks]
    
    # Generate and store embeddings
    embed_chunks_func(chunk_dicts, db_url)
    logger.info(f"Generated embeddings for {len(chunks)} chunks")


# TODO: FAISS indexing hook
def index_chunks_faiss(chunks: List[DocumentChunk], index_path: Path) -> None:
    """
    TODO: Implement FAISS indexing for chunks.
    
    This function should:
    1. Load or create FAISS index
    2. Add chunk embeddings to index
    3. Save updated index
    """
    logger.info(f"TODO: Index {len(chunks)} chunks in FAISS at {index_path}")
    pass