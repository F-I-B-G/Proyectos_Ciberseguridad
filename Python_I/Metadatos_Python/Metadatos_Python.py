from abc import ABC, abstractmethod
from PIL import Image
import mimetypes
from pdfminer.high_level import extract_text
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
import re
import docx

class MetadataExtractor(ABC):
    # Se creará un método abstracto para que en el futuro cuando se creen nuevas clases, sea de obligatoria implementación para que cada instancia
    # Tenga una interfaz común.
    @abstractmethod
    def extract(self, filepath):
        pass

class ImageMetadataExtractor(MetadataExtractor):
    def extract(self, filepath):
        # Se leerá una imagen y sus metadatos asociados:
        with Image.open(filepath) as img:
            if img.format in ['JPG', 'JPEG']:
                exif = img._getexif()
                if exif:
                    # Si no arroja un none, o sea 'exif' es True, nos retornará el valor:
                    return {Image.ExifTags.TAGS.get(key, key): value
                            for key, value in exif.items() if key in Image.ExifTags.TAGS}
                else:
                    return {'Error': 'Metadatos Exif no encontrados :('}
            elif img.format in ['PNG']:
                if img.info:
                    return img.info
                else:
                    return {'Error': 'Metadatos Exif no encontrados :('}
            else:
                return {'Error': 'Formato de imagen no soportado :P'}

class pdfMetadataExtractor(MetadataExtractor):
    def extract(self, filepath):
        metadata = {}
        with open(filepath, 'rb') as f:
            # Le pasamos el documento.
            parser = PDFParser(f)
            # Lo procesamos:
            doc = PDFDocument(parser)
            if doc.info:
                # Si este documento tiene información:
                for info in doc.info:
                    for key, value in info.items():
                        # Verificamos si el valor de las claves son bytes:
                        if isinstance(value, bytes):
                            # Si value está en bytes, se decodifica:
                            try:
                                # Se intentará decodificarlo en UTF-16BE
                                decode_value = value.decode('utf-16be')
                            except UnicodeDecodeError:
                                # Se va a intentar decodificar en UTF-8 y si no puedo, ignora todo esto y lo deja igual.
                                decode_value = value.decode('utf-8', errors='ignore')
                        else:
                            decode_value = value
                        # AL diccioanrio se le agrega una nueva key:
                        metadata[key] = decode_value
            
            # Se va a procesar el texto del PDF para la obtención de datos de interés:
            text = extract_text(filepath)
            # Le pasamos el texto extraído anteriormente al método interno 'extract'.
            metadata['Emails'] = self._extract_emails(text)
        return metadata
    
    # Se van a extraer los emails:
    def _extract_emails(self, text):
        # Va a filtrar por expresiones regulares.
        email_regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        # Va a retornar todas las coincidencias de esta expresión regular en el texto.
        return re.findall(email_regex, text)

class DocxMetadataExtract(MetadataExtractor):
    def extract(self, filepath):
        # Se lee primero el fichero
        doc = docx.Document(filepath)
        # Obtenemos las propiedades del documento:
        prop = doc.core_properties
        # Sacamos por pantalla las propiedades que queremos que salgan
        attributes = [
            "author", "category", "comments", "content_status", 
            "created", "identifier", "keywords", "last_modified_by", 
            "language", "modified", "subject", "title", "version"

        ]
        # Extraemos las propiedades:
        metadata = {attr: getattr(prop, attr, None) for attr in attributes}
        return metadata


class MetadataExtractorFactory:
    # Esta clase se encarga de crear, como si fuese una fábrica, objetos de MetadataExtractor específicos para un tipo de archivo.
    @staticmethod
    def get_extractor(filepath):
        mime_type, _ = mimetypes.guess_type(filepath)
        # Si consigue adivinar el tipo de archivo:
        if mime_type:
            if mime_type.startswith('image'):
                # Si lo anterior se cumple, me va a devolver una instancia de:
                return ImageMetadataExtractor()
            # Si el archivo es un pdf.
            if mime_type == 'application/pdf':
                return pdfMetadataExtractor()
            if mime_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
                return DocxMetadataExtract()
        raise ValueError('Tipo de fichero no soportado:(')

def extract_metadata(filepath):
    # Esta función facilitará el uso del script ya que pord etrás va a ejecutar todo lo anterior.
    extractor = MetadataExtractorFactory.get_extractor(filepath)
    return extractor.extract(filepath)