from abc import abstractmethod
from typing import Callable

from sigma.processing.pipeline import ProcessingPipeline


class Pipeline:
    """
    Base class for all pipelines. This class acts as a class decorator
    to register existing pipelines, and also as a base class for all
    the new pipelines. The reasoning behind this is discussed in:
    https://github.com/SigmaHQ/pySigma/discussions/110#discussioncomment-6179682
    """

    def __init__(
        self,
        func: Callable[[], ProcessingPipeline] | None = None,
    ):
        """
        Initialize the pipeline. If the function is set, then it is a class decorator.
        Otherwise, it is an inherited class, so we return the class itself.

        Keyword Arguments:
            func (Callable[[], ProcessingPipeline] | None): The function to be
                decorated. If None, the class is inherited. Defaults to None.
        """
        self.func = func

    def __call__(self, *args, **kwargs):
        """
        When the class is called, we call the function if set,
        otherwise we return the class itself.
        """
        if getattr(self, "apply"):
            return self.apply(*args, **kwargs)
        return self.func(*args, **kwargs) if self.func is not None else self

    @abstractmethod
    def apply(self, *args, **kwargs):
        """
        If the class is inherited, then this method must be implemented to return
        a ProcessingPipeline object. Otherwise, this method is not called.
        """
        raise NotImplementedError("The apply method must be implemented.")
