import cv2
import numpy as np
from pyzbar.pyzbar import decode
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QRDetector:
    def __init__(self):
        logger.info("Initializing QR Code Detector")
    
    def detect_qr_code_from_image(self, img):
        """
        Detect and decode QR codes directly from an in-memory image
        
        Args:
            img: OpenCV image in numpy array format
            
        Returns:
            list: List of decoded QR codes with their data
        """
        try:
            if img is None:
                logger.error("Invalid image data")
                return None
                
            return self._decode_qr_from_image(img)
                
        except Exception as e:
            logger.error(f"Error detecting QR code from memory: {str(e)}")
            return None
    
    def _decode_qr_from_image(self, img):
        """
        Internal method to decode QR codes from an image
        
        Args:
            img: OpenCV image in numpy array format
            
        Returns:
            list: List of decoded QR codes with their data
        """
        # Try to decode the QR code
        decoded_objects = decode(img)
        
        if not decoded_objects:
            logger.info("No QR code found in the image")
            return None
            
        results = []
        for obj in decoded_objects:
            qr_data = {
                'type': obj.type,
                'data': obj.data.decode('utf-8'),
                'rect': {
                    'x': obj.rect.left,
                    'y': obj.rect.top,
                    'width': obj.rect.width,
                    'height': obj.rect.height
                },
                'polygon': [(p.x, p.y) for p in obj.polygon]
            }
            results.append(qr_data)
            
        logger.info(f"Successfully detected {len(results)} QR code(s)")
        return results
            
    def draw_qr_boundary_in_memory(self, img):
        """
        Draw boundaries around detected QR codes on an in-memory image without saving
        
        Args:
            img: OpenCV image in numpy array format
            
        Returns:
            numpy.ndarray: Image with QR boundaries drawn
        """
        try:
            if img is None:
                logger.error("Invalid image data")
                return None
                
            # Make a copy of the image to avoid modifying the original
            result_img = img.copy()
            
            # Detect QR codes
            decoded_objects = decode(result_img)
            
            # Draw boundaries
            for obj in decoded_objects:
                points = obj.polygon
                # Convert points to numpy array
                pts = np.array([(p.x, p.y) for p in points], np.int32)
                pts = pts.reshape((-1, 1, 2))
                # Draw polygon
                cv2.polylines(result_img, [pts], True, (0, 255, 0), 3)
                
                # Add data text
                data = obj.data.decode('utf-8')
                x = obj.rect.left
                y = obj.rect.top - 10
                cv2.putText(result_img, data[:20] + "..." if len(data) > 20 else data, 
                            (x, y), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)
            
            logger.info("Generated in-memory image with QR boundaries")
            return result_img
                
        except Exception as e:
            logger.error(f"Error drawing QR boundaries in memory: {str(e)}")
            return img  # Return original image on error 