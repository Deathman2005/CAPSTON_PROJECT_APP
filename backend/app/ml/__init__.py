"""Machine learning module for SMS Shield."""

from app.ml.preprocessor import SmsPreprocessor
from app.ml.features import LinguisticFeatureExtractor, extract_explanation_reasons
from app.ml.dataset import DatasetManager, DatasetMetadata
from app.ml.trainer import SmsModelTrainer
from app.ml.service import SmsClassifierService, SmsClassificationResult
from app.ml.url_features import UrlFeatureExtractor, extract_url_features_dict
from app.ml.url_trainer import UrlModelTrainer
from app.ml.url_service import UrlClassifierService, UrlClassificationResult

__all__ = [
    "SmsPreprocessor",
    "LinguisticFeatureExtractor",
    "extract_explanation_reasons",
    "DatasetManager",
    "DatasetMetadata",
    "SmsModelTrainer",
    "SmsClassifierService",
    "SmsClassificationResult",
    "UrlFeatureExtractor",
    "extract_url_features_dict",
    "UrlModelTrainer",
    "UrlClassifierService",
    "UrlClassificationResult",
]
