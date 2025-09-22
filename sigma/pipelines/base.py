from abc import abstractmethod
from typing import Any, Optional, Callable

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

    def __call__(self, *args: list[Any], **kwargs: dict[str, Any]) -> Any:
        """
        When the class is called, we call the function if set,
        otherwise we return the class itself.
        """
        apply_method = getattr(self, "apply", None)
        if callable(apply_method) and not getattr(apply_method, "__isabstractmethod__", False):
            return apply_method(*args, **kwargs)
        return self.func(*args, **kwargs) if self.func is not None else self

    def __new__(cls, *args: list[Any], **kwargs: dict[str, Any]) -> "Pipeline":
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
