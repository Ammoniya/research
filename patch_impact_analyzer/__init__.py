"""Patch impact analysis module."""

from .php_parser import PHPCodeParser
from .call_graph import CallGraphBuilder
from .data_flow import DataFlowAnalyzer
from .control_flow import ControlFlowGraphBuilder
from .impact_analyzer import PatchImpactAnalyzer
from .models import (
    CodeElement,
    FunctionDefinition,
    FunctionCall,
    VariableUsage,
    CallGraph,
    DataFlowGraph,
    ControlFlowGraph,
    ImpactAnalysis
)

__all__ = [
    'PHPCodeParser',
    'CallGraphBuilder',
    'DataFlowAnalyzer',
    'ControlFlowGraphBuilder',
    'PatchImpactAnalyzer',
    'CodeElement',
    'FunctionDefinition',
    'FunctionCall',
    'VariableUsage',
    'CallGraph',
    'DataFlowGraph',
    'ControlFlowGraph',
    'ImpactAnalysis'
]
