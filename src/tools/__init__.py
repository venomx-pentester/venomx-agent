"""
Tool Registry and Factory
Central access point for all security tools
"""

from typing import Optional
from .base import BaseTool, ToolResult, ToolStatus
from .nmap import NmapTool
from .searchsploit import SearchsploitTool

# TODO: Import additional tools as they're implemented
# from .nikto import NiktoTool
# from .gobuster import GobusterTool
# from .hydra import HydraTool
# from .sqlmap import SQLMapTool
# from .metasploit import MetasploitTool


class ToolFactory:
    """
    Factory for creating tool instances
    Provides centralized tool access and management
    """

    _tools: dict[str, type[BaseTool]] = {
        "nmap": NmapTool,
        "searchsploit": SearchsploitTool,
        # TODO: Add more tools
        # "nikto": NiktoTool,
        # "gobuster": GobusterTool,
        # "hydra": HydraTool,
        # "sqlmap": SQLMapTool,
        # "metasploit": MetasploitTool,
    }

    @classmethod
    def get_tool(cls, tool_name: str) -> Optional[BaseTool]:
        """
        Get an instance of the specified tool

        Args:
            tool_name: Name of the tool (e.g., "nmap", "nikto")

        Returns:
            Tool instance or None if tool not found
        """
        tool_class = cls._tools.get(tool_name.lower())
        if tool_class:
            return tool_class()
        return None

    @classmethod
    def list_tools(cls) -> list[str]:
        """Get list of available tool names"""
        return list(cls._tools.keys())

    @classmethod
    def register_tool(cls, name: str, tool_class: type[BaseTool]):
        """
        Register a new tool (for extensibility)

        Args:
            name: Tool name
            tool_class: Tool class inheriting from BaseTool
        """
        cls._tools[name.lower()] = tool_class


# Convenience exports
__all__ = [
    "BaseTool",
    "ToolResult",
    "ToolStatus",
    "ToolFactory",
    "NmapTool",
    "SearchsploitTool",
]