import logging
from pathlib import Path

# Make spdx_tools imports optional
try:
    from spdx_tools.spdx.parser import parse_anything
    from spdx_tools.spdx.writer.json.json_writer import write_document_to_file
    from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
    SPDX_TOOLS_AVAILABLE = True
except ImportError:
    SPDX_TOOLS_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def convert_spdx_to_json(spdx_file_path, json_output_path=None):
    """Convert SPDX file to JSON format using spdx-tools"""
    if not SPDX_TOOLS_AVAILABLE:
        raise ImportError("spdx_tools package is not installed. Please install it with: pip install spdx-tools")
    
    try:
        # Ensure input path is absolute
        spdx_file_path = str(Path(spdx_file_path).resolve())
        
        # Set default output path if none provided
        if json_output_path is None:
            json_output_path = str(Path(spdx_file_path).with_suffix('.json'))
        else:
            json_output_path = str(Path(json_output_path).resolve())
            
        logger.info(f"Converting {spdx_file_path} to JSON format...")
        
        # Parse the SPDX file
        document = parse_anything.parse_file(spdx_file_path)
        if document is None:
            raise ValueError("Failed to parse SPDX file")
        
        # Validate the document before writing
        validation_errors = validate_full_spdx_document(document)
        if validation_errors:
            logger.warning("Document validation produced warnings:")
            for error in validation_errors:
                logger.warning(f"- {error}")
            
        # Write to JSON format with validation disabled since we handled it above
        write_document_to_file(document, json_output_path, validate=False)
        
        logger.info(f"Successfully converted to {json_output_path}")
        return json_output_path

    except Exception as e:
        logger.error(f"Error converting SPDX file: {str(e)}")
        raise

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        spdx_input_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        convert_spdx_to_json(spdx_input_file, output_file)
    else:
        print("Usage: python converter.py <input.spdx> [output.json]")
