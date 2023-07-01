from abc import abstractmethod
from typing import Optional, Callable

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
        func: Optional[Callable[[], ProcessingPipeline]] = None,
    ):
        """
        Initialize the pipeline. If the function is set, then it is a class decorator.
        Otherwise, it is an inherited class, so we return the class itself.

        Keyword Arguments:
            func (Optional[Callable[[], ProcessingPipeline]]): The function to be
                decorated. If None, the class is inherited. Defaults to None.
        """
        self.func = func

    def __call__(self, *args, **kwargs):
        """
        When the class is called, we call the function if set,
        otherwise we return the class itself.
        """
        if getattr(self, "apply") and not self.apply.__isabstractmethod__:
            return self.apply(*args, **kwargs)
        return self.func(*args, **kwargs) if self.func is not None else self

    def __new__(cls, *args, **kwargs):
        """
        Use the singleton pattern to ensure that only one instance of the class
        is created. This is necessary to ensure that the pipelines are registered
        only once if the class is inherited.

        Args:
            cls ([type]): The class itself.
            *args: The arguments to be passed to the class constructor.

        Keyword Arguments:
            **kwargs: The keyword arguments to be passed to the class constructor.

        Returns:
            Pipeline: The class instance.
        """
        if not hasattr(cls, "_instance"):
            cls._instance = super(Pipeline, cls).__new__(cls)
        return cls._instance

    @abstractmethod
    def apply(self, *args, **kwargs):
        """
        If the class is inherited, then this method must be implemented to return
        a ProcessingPipeline object. Otherwise, this method is not called.
        """
        raise NotImplementedError("The apply method must be implemented.")
