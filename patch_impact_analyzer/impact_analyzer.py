"""Main patch impact analyzer that integrates all analysis components."""

from typing import Dict, List, Optional
from pathlib import Path
import json

from .php_parser import PHPCodeParser
from .call_graph import CallGraphBuilder
from .data_flow import DataFlowAnalyzer
from .control_flow import ControlFlowGraphBuilder
from .models import (
    ImpactAnalysis,
    ImpactRelationship,
    CallGraph,
    DataFlowGraph,
    ControlFlowGraph
)


class PatchImpactAnalyzer:
    """
    Analyzes the impact of one CVE patch on another.

    This class integrates call graph, data flow, and control flow analysis
    to determine how patches relate to each other.
    """

    def __init__(self):
        """Initialize the patch impact analyzer."""
        self.parser = PHPCodeParser()
        self.call_graph_builder = CallGraphBuilder()
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.control_flow_builder = ControlFlowGraphBuilder()

    def analyze_patch_impact(self,
                            cve1_data: Dict,
                            cve2_data: Dict,
                            verbose: bool = False) -> ImpactAnalysis:
        """
        Analyze the impact relationship between two CVE patches.

        Args:
            cve1_data: First CVE patch data (must have pre_patch_code, post_patch_code)
            cve2_data: Second CVE patch data
            verbose: Whether to print verbose output

        Returns:
            ImpactAnalysis object with detailed relationship information
        """
        cve1_id = cve1_data.get('cve', 'CVE-1')
        cve2_id = cve2_data.get('cve', 'CVE-2')

        if verbose:
            print(f"Analyzing impact: {cve1_id} -> {cve2_id}")

        analysis = ImpactAnalysis(cve1=cve1_id, cve2=cve2_id)

        # Extract code from CVE data
        cve1_pre = cve1_data.get('pre_patch_code', '')
        cve1_post = cve1_data.get('post_patch_code', '')
        cve2_pre = cve2_data.get('pre_patch_code', '')
        cve2_post = cve2_data.get('post_patch_code', '')

        if not cve1_post or not cve2_post:
            if verbose:
                print("Warning: Missing patch code data")
            return analysis

        # Build call graphs
        if verbose:
            print("  Building call graphs...")

        cve1_call_graph = self.call_graph_builder.build_call_graph(cve1_post, f"{cve1_id}")
        cve2_call_graph = self.call_graph_builder.build_call_graph(cve2_post, f"{cve2_id}")

        # Compare call graphs
        call_graph_comparison = self.call_graph_builder.compare_call_graphs(
            cve1_call_graph, cve2_call_graph
        )

        analysis.shared_functions = call_graph_comparison['shared_functions']
        analysis.call_graph_overlap = call_graph_comparison['overlap_percentage']
        analysis.upstream_impacts = call_graph_comparison['graph1_upstream']
        analysis.downstream_impacts = call_graph_comparison['graph1_downstream']

        # Add call graph relationship
        if analysis.shared_functions:
            rel = ImpactRelationship(
                relationship_type="function_overlap",
                description=f"Found {len(analysis.shared_functions)} shared functions between patches",
                confidence=min(1.0, len(analysis.shared_functions) / 10),
                evidence=[f"Shared function: {func}" for func in analysis.shared_functions[:5]]
            )
            analysis.add_relationship(rel)

        # Build data flow graphs
        if verbose:
            print("  Building data flow graphs...")

        cve1_data_flow = self.data_flow_analyzer.build_data_flow_graph(cve1_post, f"{cve1_id}")
        cve2_data_flow = self.data_flow_analyzer.build_data_flow_graph(cve2_post, f"{cve2_id}")

        # Compare data flows
        data_flow_comparison = self.data_flow_analyzer.compare_data_flows(
            cve1_data_flow, cve2_data_flow
        )

        analysis.shared_variables = data_flow_comparison['shared_variables']
        analysis.data_flow_chains = data_flow_comparison['flow_chains']
        analysis.tainted_variables = data_flow_comparison['tainted_variables']

        # Add data flow relationship
        if analysis.shared_variables:
            rel = ImpactRelationship(
                relationship_type="variable_overlap",
                description=f"Found {len(analysis.shared_variables)} shared variables between patches",
                confidence=min(1.0, len(analysis.shared_variables) / 15),
                evidence=[f"Shared variable: {var}" for var in analysis.shared_variables[:5]]
            )
            analysis.add_relationship(rel)

        # Add data flow chain relationship
        if analysis.data_flow_chains:
            rel = ImpactRelationship(
                relationship_type="data_flow_chain",
                description=f"Found {len(analysis.data_flow_chains)} data flow chains connecting the patches",
                confidence=min(1.0, len(analysis.data_flow_chains) / 5),
                evidence=[f"Flow chain: {' -> '.join(chain)}" for chain in analysis.data_flow_chains[:3]]
            )
            analysis.add_relationship(rel)

        # Build control flow graphs
        if verbose:
            print("  Building control flow graphs...")

        cve1_cfg = self.control_flow_builder.build_control_flow_graph(cve1_post, f"{cve1_id}")
        cve2_cfg = self.control_flow_builder.build_control_flow_graph(cve2_post, f"{cve2_id}")

        # Compare control flow
        cfg_comparison = self.control_flow_builder.compare_control_flow_graphs(
            cve1_cfg, cve2_cfg
        )

        analysis.control_flow_changes = cfg_comparison['path_changes']

        # Add control flow relationship
        if cfg_comparison['structural_similarity'] > 0.5:
            rel = ImpactRelationship(
                relationship_type="control_flow_change",
                description=f"Control flow similarity: {cfg_comparison['structural_similarity']:.2%}",
                confidence=cfg_comparison['structural_similarity'],
                evidence=cfg_comparison['path_changes'][:3]
            )
            analysis.add_relationship(rel)

        # Analyze file overlap
        cve1_file = cve1_data.get('patch_location', '')
        cve2_file = cve2_data.get('patch_location', '')

        if cve1_file and cve2_file:
            # Extract file paths from patch location
            cve1_files = self._extract_file_paths(cve1_file)
            cve2_files = self._extract_file_paths(cve2_file)

            analysis.shared_files = list(set(cve1_files).intersection(set(cve2_files)))

        if verbose:
            print(f"  Impact Score: {analysis.impact_score:.2f}")
            print(f"  Impact Level: {analysis.impact_level}")

        return analysis

    def analyze_temporal_impact(self,
                                earlier_cve: Dict,
                                later_cve: Dict,
                                verbose: bool = False) -> Dict:
        """
        Analyze how an earlier CVE patch impacts a later CVE.

        This considers the temporal ordering and analyzes if the earlier
        patch affects the code that the later patch modifies.

        Args:
            earlier_cve: CVE data for the earlier patch
            later_cve: CVE data for the later patch
            verbose: Whether to print verbose output

        Returns:
            Dict with temporal impact analysis
        """
        if verbose:
            print(f"Temporal analysis: {earlier_cve.get('cve')} -> {later_cve.get('cve')}")

        # Regular impact analysis
        impact = self.analyze_patch_impact(earlier_cve, later_cve, verbose)

        # Additional temporal analysis
        temporal_data = {
            'impact_analysis': impact,
            'temporal_order': 'earlier -> later',
            'earlier_cve': earlier_cve.get('cve'),
            'later_cve': later_cve.get('cve'),
        }

        # Check if earlier patch's post-code matches later patch's pre-code
        earlier_post = earlier_cve.get('post_patch_code', '')
        later_pre = later_cve.get('pre_patch_code', '')

        if earlier_post and later_pre:
            similarity = self._code_similarity(earlier_post, later_pre)
            temporal_data['code_continuity'] = similarity

            if similarity > 0.7:
                temporal_data['note'] = "High code continuity - later patch likely builds on earlier patch"
            elif similarity > 0.4:
                temporal_data['note'] = "Moderate code continuity - patches may affect related code"
            else:
                temporal_data['note'] = "Low code continuity - patches appear independent"

        return temporal_data

    def compare_multiple_patches(self,
                                cve_data_list: List[Dict],
                                output_dir: Optional[Path] = None,
                                verbose: bool = False) -> Dict:
        """
        Compare multiple CVE patches to find relationships.

        Only compares CVEs within the same plugin to find related vulnerabilities.

        Args:
            cve_data_list: List of CVE patch data dicts
            output_dir: Optional directory to save results
            verbose: Whether to print verbose output

        Returns:
            Dict with all pairwise comparisons
        """
        # Group CVEs by plugin
        from collections import defaultdict
        plugins = defaultdict(list)

        for cve_data in cve_data_list:
            plugin_slug = cve_data.get('plugin_slug', 'unknown')
            plugins[plugin_slug].append(cve_data)

        if verbose:
            print(f"Grouped {len(cve_data_list)} CVEs into {len(plugins)} plugins")
            for plugin, cves in plugins.items():
                print(f"  {plugin}: {len(cves)} CVEs")

        # Calculate total comparisons
        total_comparisons = sum(
            len(cves) * (len(cves) - 1) // 2
            for cves in plugins.values()
        )

        if verbose:
            print(f"Will perform {total_comparisons} within-plugin comparisons\n")

        results = {
            'total_cves': len(cve_data_list),
            'total_plugins': len(plugins),
            'plugin_groups': {plugin: len(cves) for plugin, cves in plugins.items()},
            'comparisons': [],
            'high_impact_pairs': [],
            'summary': {}
        }

        # Perform pairwise comparisons within each plugin
        for plugin_slug, plugin_cves in plugins.items():
            if len(plugin_cves) < 2:
                if verbose:
                    print(f"Skipping {plugin_slug} (only {len(plugin_cves)} CVE)")
                continue

            if verbose:
                print(f"\n{'='*60}")
                print(f"Analyzing plugin: {plugin_slug} ({len(plugin_cves)} CVEs)")
                print(f"{'='*60}")

            # Compare CVEs within this plugin
            for i in range(len(plugin_cves)):
                for j in range(i + 1, len(plugin_cves)):
                    cve1 = plugin_cves[i]
                    cve2 = plugin_cves[j]

                    if verbose:
                        print(f"\nComparing {cve1.get('cve')} vs {cve2.get('cve')}")

                    impact = self.analyze_patch_impact(cve1, cve2, verbose=verbose)

                    comparison = {
                        'plugin': plugin_slug,
                        'cve1': cve1.get('cve'),
                        'cve2': cve2.get('cve'),
                        'impact_score': impact.impact_score,
                        'impact_level': impact.impact_level,
                        'shared_functions': len(impact.shared_functions),
                        'shared_variables': len(impact.shared_variables),
                        'relationships': len(impact.relationships)
                    }

                    results['comparisons'].append(comparison)

                    # Track high impact pairs
                    if impact.impact_score >= 60:
                        results['high_impact_pairs'].append({
                            'plugin': plugin_slug,
                            'pair': f"{cve1.get('cve')} <-> {cve2.get('cve')}",
                            'score': impact.impact_score,
                            'level': impact.impact_level
                        })

        # Generate summary statistics
        if results['comparisons']:
            scores = [c['impact_score'] for c in results['comparisons']]
            results['summary'] = {
                'average_impact_score': sum(scores) / len(scores),
                'max_impact_score': max(scores),
                'min_impact_score': min(scores),
                'high_impact_count': len(results['high_impact_pairs']),
                'total_comparisons': len(results['comparisons'])
            }
        else:
            results['summary'] = {
                'average_impact_score': 0.0,
                'max_impact_score': 0.0,
                'min_impact_score': 0.0,
                'high_impact_count': 0,
                'total_comparisons': 0
            }

        # Save results if output directory specified
        if output_dir:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            output_file = output_dir / "patch_impact_analysis.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)

            if verbose:
                print(f"\nResults saved to {output_file}")

        return results

    def _extract_file_paths(self, patch_location: str) -> List[str]:
        """
        Extract file paths from patch location string.

        Args:
            patch_location: Patch location string

        Returns:
            List of file paths
        """
        # Simple extraction - split by common separators
        import re
        files = re.findall(r'[\w/\-\.]+\.php', patch_location)
        return files

    def _code_similarity(self, code1: str, code2: str) -> float:
        """
        Calculate similarity between two code snippets.

        Args:
            code1: First code snippet
            code2: Second code snippet

        Returns:
            Similarity score (0.0 to 1.0)
        """
        import re

        # Tokenize
        tokens1 = set(re.findall(r'\w+', code1.lower()))
        tokens2 = set(re.findall(r'\w+', code2.lower()))

        if not tokens1 or not tokens2:
            return 0.0

        # Jaccard similarity
        intersection = tokens1.intersection(tokens2)
        union = tokens1.union(tokens2)

        return len(intersection) / len(union) if union else 0.0

    def generate_report(self, analysis: ImpactAnalysis, output_file: Optional[Path] = None) -> str:
        """
        Generate a detailed report from an impact analysis.

        Args:
            analysis: ImpactAnalysis object
            output_file: Optional file path to save the report

        Returns:
            Report as markdown string
        """
        report = analysis.to_markdown()

        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(report)

        return report
