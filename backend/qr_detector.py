import cv2
import numpy as np
from pyzbar.pyzbar import decode
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QRDetector:
    def __init__(self):
        logger.info("Initializing QR Code Detector")
    
    def detect_qr_code(self, image_path):
        """
        Detect and decode QR codes from an image
        
        Args:
            image_path (str): Path to the image file
            
        Returns:
            list: List of decoded QR codes with their data
        """
        try:
            # Check if file exists
            if not os.path.exists(image_path):
                logger.error(f"Image file not found: {image_path}")
                return None
                
            # Read the image
            img = cv2.imread(image_path)
            if img is None:
                logger.error(f"Failed to read image: {image_path}")
                return None
                
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
            
        except Exception as e:
            logger.error(f"Error detecting QR code: {str(e)}")
            return None
            
    def draw_qr_boundary(self, image_path, output_path=None):
        """
        Draw boundaries around detected QR codes and save to a new image
        
        Args:
            image_path (str): Path to the input image
            output_path (str, optional): Path to save the output image
            
        Returns:
            str: Path to the saved image with QR boundaries
        """
        try:
            # Read the image
            img = cv2.imread(image_path)
            if img is None:
                logger.error(f"Failed to read image: {image_path}")
                return None
                
            # Detect QR codes
            decoded_objects = decode(img)
            
            # Draw boundaries
            for obj in decoded_objects:
                points = obj.polygon
                # Convert points to numpy array
                pts = np.array([(p.x, p.y) for p in points], np.int32)
                pts = pts.reshape((-1, 1, 2))
                # Draw polygon
                cv2.polylines(img, [pts], True, (0, 255, 0), 3)
                
                # Add data text
                data = obj.data.decode('utf-8')
                x = obj.rect.left
                y = obj.rect.top - 10
                cv2.putText(img, data[:20] + "..." if len(data) > 20 else data, 
                            (x, y), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)
            
            # Save or return the image
            if output_path:
                cv2.imwrite(output_path, img)
                logger.info(f"Saved image with QR boundaries to {output_path}")
                return output_path
            else:
                # Generate a filename if not provided
                base_name = os.path.basename(image_path)
                name, ext = os.path.splitext(base_name)
                output_path = f"{name}_qr_detected{ext}"
                cv2.imwrite(output_path, img)
                logger.info(f"Saved image with QR boundaries to {output_path}")
                return output_path
                
        except Exception as e:
            logger.error(f"Error drawing QR boundaries: {str(e)}")
            return None 