import cv2
import numpy as np

class Operator:
    def operate(self, operation, image):
        method_name = 'command_' + operation
        method = getattr(self, method_name)
        nparr = np.fromstring(image, np.uint8)
        img_np = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        img = method(img_np)

        img = cv2.imencode('.jpg', img)[1]

        return img
    
    def command_gaussian_filter(self, image):
        return cv2.GaussianBlur(image, (5,5), 0)

    def command_median_filtering(self, image):
        return cv2.medianBlur(image, 5)

    def command_averaging(self, image):
        return cv2.blur(image, (5,5))
    
    def command_laplacian(self, image):
        return cv2.Laplacian(image, cv2.CV_64F)