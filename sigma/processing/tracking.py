from dataclasses import dataclass, field
import sigma
from typing import Optional, Set

@dataclass
class ProcessingItemTrackingMixin:
    """
    Provides attributes and methods for tracking processing items applied to Sigma rule objects
    like detection items and conditions.
    """
    applied_processing_items : Set[str] = field(init=False, compare=False, default_factory=set)

    def add_applied_processing_item(self, processing_item : Optional["sigma.processing.pipeline.ProcessingItem"]):
        """Add identifier of processing item to set of applied processing items."""
        if processing_item is not None and processing_item.identifier is not None:
            self.applied_processing_items.add(processing_item.identifier)

    def was_processed_by(self, processing_item_id : str) -> bool:
        """Determines if detection item was processed by a processing item with the given id."""
        return processing_item_id in self.applied_processing_items