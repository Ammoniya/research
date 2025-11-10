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
            print(f"\n{'='*60}")
            print(f"Analyzing impact: {cve1_id} -> {cve2_id}")
            print(f"{'='*60}")

        analysis = ImpactAnalysis(cve1=cve1_id, cve2=cve2_id)

        # Extract code from CVE data
        cve1_pre = cve1_data.get('pre_patch_code', '')
        cve1_post = cve1_data.get('post_patch_code', '')
        cve2_pre = cve2_data.get('pre_patch_code', '')
        cve2_post = cve2_data.get('post_patch_code', '')

        if verbose:
            print(f"\nCode extraction:")
            print(f"  CVE1 pre-patch:  {len(cve1_pre):>6} chars")
            print(f"  CVE1 post-patch: {len(cve1_post):>6} chars")
            print(f"  CVE2 pre-patch:  {len(cve2_pre):>6} chars")
            print(f"  CVE2 post-patch: {len(cve2_post):>6} chars")

        if not cve1_post or not cve2_post:
            if verbose:
                print("\n⚠️  Warning: Missing patch code data - analysis incomplete")
            return analysis

        # Build call graphs
        if verbose:
            print(f"\n[1/3] Building call graphs...")

        cve1_call_graph = self.call_graph_builder.build_call_graph(cve1_post, f"{cve1_id}")
        cve2_call_graph = self.call_graph_builder.build_call_graph(cve2_post, f"{cve2_id}")

        if verbose:
            print(f"  CVE1 functions: {len(cve1_call_graph.nodes)}")
            print(f"  CVE2 functions: {len(cve2_call_graph.nodes)}")
            cve1_total_calls = sum(len(callees) for callees in cve1_call_graph.edges.values())
            cve2_total_calls = sum(len(callees) for callees in cve2_call_graph.edges.values())
            print(f"  CVE1 calls: {cve1_total_calls}")
            print(f"  CVE2 calls: {cve2_total_calls}")

        # Compare call graphs
        if verbose:
            print(f"  Comparing call graphs...")

        call_graph_comparison = self.call_graph_builder.compare_call_graphs(
            cve1_call_graph, cve2_call_graph
        )

        analysis.shared_functions = call_graph_comparison['shared_functions']
        analysis.call_graph_overlap = call_graph_comparison['overlap_percentage']
        analysis.upstream_impacts = call_graph_comparison['graph1_upstream']
        analysis.downstream_impacts = call_graph_comparison['graph1_downstream']

        if verbose:
            print(f"  ✓ Shared functions: {len(analysis.shared_functions)}")
            print(f"  ✓ Call graph overlap: {analysis.call_graph_overlap:.1f}%")
            print(f"  ✓ Upstream impacts: {len(analysis.upstream_impacts)}")
            print(f"  ✓ Downstream impacts: {len(analysis.downstream_impacts)}")
            if analysis.shared_functions:
                print(f"    Examples: {', '.join(list(analysis.shared_functions)[:3])}")

        # Add call graph relationship
        if analysis.shared_functions:
            rel = ImpactRelationship(
                relationship_type="function_overlap",
                description=f"Found {len(analysis.shared_functions)} shared functions between patches",
                confidence=min(1.0, len(analysis.shared_functions) / 10),
                evidence=[f"Shared function: {func}" for func in analysis.shared_functions[:5]]
            )
            analysis.add_relationship(rel)
            if verbose:
                print(f"    → Added function_overlap relationship (confidence: {rel.confidence:.2f})")

        # Build data flow graphs
        if verbose:
            print(f"\n[2/3] Building data flow graphs...")

        cve1_data_flow = self.data_flow_analyzer.build_data_flow_graph(cve1_post, f"{cve1_id}")
        cve2_data_flow = self.data_flow_analyzer.build_data_flow_graph(cve2_post, f"{cve2_id}")

        if verbose:
            print(f"  CVE1 variables: {len(cve1_data_flow.variable_flows)}")
            print(f"  CVE2 variables: {len(cve2_data_flow.variable_flows)}")
            print(f"  CVE1 flows: {len(cve1_data_flow.edges)}")
            print(f"  CVE2 flows: {len(cve2_data_flow.edges)}")

        # Compare data flows
        if verbose:
            print(f"  Comparing data flows...")

        data_flow_comparison = self.data_flow_analyzer.compare_data_flows(
            cve1_data_flow, cve2_data_flow
        )

        analysis.shared_variables = data_flow_comparison['shared_variables']
        analysis.data_flow_chains = data_flow_comparison['flow_chains']
        analysis.tainted_variables = data_flow_comparison['tainted_variables']

        if verbose:
            print(f"  ✓ Shared variables: {len(analysis.shared_variables)}")
            print(f"  ✓ Data flow chains: {len(analysis.data_flow_chains)}")
            print(f"  ✓ Tainted variables: {len(analysis.tainted_variables)}")
            if analysis.shared_variables:
                print(f"    Examples: {', '.join(list(analysis.shared_variables)[:3])}")

        # Add data flow relationship
        if analysis.shared_variables:
            rel = ImpactRelationship(
                relationship_type="variable_overlap",
                description=f"Found {len(analysis.shared_variables)} shared variables between patches",
                confidence=min(1.0, len(analysis.shared_variables) / 15),
                evidence=[f"Shared variable: {var}" for var in analysis.shared_variables[:5]]
            )
            analysis.add_relationship(rel)
            if verbose:
                print(f"    → Added variable_overlap relationship (confidence: {rel.confidence:.2f})")

        # Add data flow chain relationship
        if analysis.data_flow_chains:
            rel = ImpactRelationship(
                relationship_type="data_flow_chain",
                description=f"Found {len(analysis.data_flow_chains)} data flow chains connecting the patches",
                confidence=min(1.0, len(analysis.data_flow_chains) / 5),
                evidence=[f"Flow chain: {' -> '.join(chain)}" for chain in analysis.data_flow_chains[:3]]
            )
            analysis.add_relationship(rel)
            if verbose:
                print(f"    → Added data_flow_chain relationship (confidence: {rel.confidence:.2f})")
                for i, chain in enumerate(analysis.data_flow_chains[:3], 1):
                    print(f"      Chain {i}: {' -> '.join(chain)}")

        # Build control flow graphs
        if verbose:
            print(f"\n[3/3] Building control flow graphs...")

        cve1_cfg = self.control_flow_builder.build_control_flow_graph(cve1_post, f"{cve1_id}")
        cve2_cfg = self.control_flow_builder.build_control_flow_graph(cve2_post, f"{cve2_id}")

        if verbose:
            print(f"  CVE1 blocks: {len(cve1_cfg.nodes)}")
            print(f"  CVE2 blocks: {len(cve2_cfg.nodes)}")
            print(f"  CVE1 edges: {len(cve1_cfg.edges)}")
            print(f"  CVE2 edges: {len(cve2_cfg.edges)}")

        # Compare control flow
        if verbose:
            print(f"  Comparing control flow graphs...")

        cfg_comparison = self.control_flow_builder.compare_control_flow_graphs(
            cve1_cfg, cve2_cfg
        )

        analysis.control_flow_changes = cfg_comparison['path_changes']

        if verbose:
            print(f"  ✓ Structural similarity: {cfg_comparison['structural_similarity']:.2%}")
            print(f"  ✓ Path changes: {len(analysis.control_flow_changes)}")

        # Add control flow relationship
        if cfg_comparison['structural_similarity'] > 0.5:
            rel = ImpactRelationship(
                relationship_type="control_flow_change",
                description=f"Control flow similarity: {cfg_comparison['structural_similarity']:.2%}",
                confidence=cfg_comparison['structural_similarity'],
                evidence=cfg_comparison['path_changes'][:3]
            )
            analysis.add_relationship(rel)
            if verbose:
                print(f"    → Added control_flow_change relationship (confidence: {rel.confidence:.2f})")

        # Analyze file overlap
        cve1_file = cve1_data.get('patch_location', '')
        cve2_file = cve2_data.get('patch_location', '')

        if verbose:
            print(f"\nFile overlap analysis:")
            print(f"  CVE1 location: {cve1_file if cve1_file else '(not specified)'}")
            print(f"  CVE2 location: {cve2_file if cve2_file else '(not specified)'}")

        if cve1_file and cve2_file:
            # Extract file paths from patch location
            cve1_files = self._extract_file_paths(cve1_file)
            cve2_files = self._extract_file_paths(cve2_file)

            analysis.shared_files = list(set(cve1_files).intersection(set(cve2_files)))

            if verbose:
                print(f"  ✓ Shared files: {len(analysis.shared_files)}")
                if analysis.shared_files:
                    for f in analysis.shared_files:
                        print(f"    - {f}")

        if verbose:
            print(f"\n{'='*60}")
            print(f"Analysis complete:")
            print(f"  Impact Score: {analysis.impact_score:.2f}/100")
            print(f"  Impact Level: {analysis.impact_level}")
            print(f"  Relationships: {len(analysis.relationships)}")
            print(f"{'='*60}\n")

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
                                verbose: bool = False,
                                adjacent_only: bool = True,
                                date_field: str = None) -> Dict:
        """
        Compare multiple CVE patches to find relationships.

        Only compares CVEs within the same plugin. By default, compares only
        adjacent CVEs in chronological order (how each patch impacts the next).

        Args:
            cve_data_list: List of CVE patch data dicts
            output_dir: Optional directory to save results
            verbose: Whether to print verbose output
            adjacent_only: If True, only compare chronologically adjacent CVEs.
                          If False, compare all pairs within each plugin.
            date_field: Field name containing release date/timestamp for sorting.
                       If None, uses CVE ID for chronological ordering.

        Returns:
            Dict with all pairwise comparisons
        """
        # Group CVEs by plugin
        from collections import defaultdict
        plugins = defaultdict(list)

        if verbose:
            print(f"\nGrouping CVEs by plugin...")

        for cve_data in cve_data_list:
            plugin_slug = cve_data.get('plugin_slug', 'unknown')
            plugins[plugin_slug].append(cve_data)

        if verbose:
            print(f"✓ Grouped {len(cve_data_list)} CVEs into {len(plugins)} plugins:")
            for plugin, cves in sorted(plugins.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
                print(f"  • {plugin}: {len(cves)} CVEs")
            if len(plugins) > 10:
                print(f"  ... and {len(plugins) - 10} more plugins")

        # Sort CVEs within each plugin chronologically
        if verbose:
            print(f"\nSorting CVEs chronologically within each plugin...")

        for plugin_slug in plugins:
            plugins[plugin_slug] = self._sort_cves_chronologically(
                plugins[plugin_slug], date_field, verbose=False  # Avoid duplicate verbose output
            )

        # Calculate total comparisons
        if adjacent_only:
            total_comparisons = sum(
                max(0, len(cves) - 1)  # n-1 adjacent pairs
                for cves in plugins.values()
            )
            comparison_mode = "adjacent (chronological)"
        else:
            total_comparisons = sum(
                len(cves) * (len(cves) - 1) // 2  # all pairs
                for cves in plugins.values()
            )
            comparison_mode = "all pairs"

        if verbose:
            print(f"✓ Chronological sorting complete")
            print(f"\nComparison strategy: {comparison_mode}")
            print(f"Total comparisons to perform: {total_comparisons}\n")

        results = {
            'total_cves': len(cve_data_list),
            'total_plugins': len(plugins),
            'plugin_groups': {plugin: len(cves) for plugin, cves in plugins.items()},
            'comparison_mode': comparison_mode,
            'comparisons': [],
            'high_impact_pairs': [],
            'summary': {}
        }

        # Perform comparisons within each plugin
        comparison_count = 0
        for plugin_idx, (plugin_slug, plugin_cves) in enumerate(plugins.items(), 1):
            if len(plugin_cves) < 2:
                if verbose:
                    print(f"[{plugin_idx}/{len(plugins)}] Skipping {plugin_slug} (only {len(plugin_cves)} CVE)")
                continue

            if verbose:
                print(f"\n{'='*60}")
                print(f"[{plugin_idx}/{len(plugins)}] Analyzing plugin: {plugin_slug} ({len(plugin_cves)} CVEs)")
                cve_list = ', '.join([c.get('cve', 'unknown') for c in plugin_cves])
                print(f"Chronological order: {cve_list}")
                print(f"{'='*60}")

            if adjacent_only:
                # Only compare adjacent CVEs in chronological order
                for i in range(len(plugin_cves) - 1):
                    cve1 = plugin_cves[i]      # Earlier CVE
                    cve2 = plugin_cves[i + 1]  # Next CVE
                    comparison_count += 1

                    if verbose:
                        print(f"\n[Comparison {comparison_count}/{total_comparisons}]")
                        print(f"Comparing {cve1.get('cve')} → {cve2.get('cve')} (adjacent chronological pair)")

                    impact = self.analyze_patch_impact(cve1, cve2, verbose=verbose)

                    comparison = {
                        'plugin': plugin_slug,
                        'cve1': cve1.get('cve'),
                        'cve2': cve2.get('cve'),
                        'temporal_relationship': 'adjacent',
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
                            'pair': f"{cve1.get('cve')} -> {cve2.get('cve')}",
                            'score': impact.impact_score,
                            'level': impact.impact_level
                        })
                        if verbose:
                            print(f"⚠️  HIGH IMPACT DETECTED: {impact.impact_score:.2f} ({impact.impact_level})")
            else:
                # Compare all pairs within this plugin
                for i in range(len(plugin_cves)):
                    for j in range(i + 1, len(plugin_cves)):
                        cve1 = plugin_cves[i]
                        cve2 = plugin_cves[j]
                        comparison_count += 1

                        if verbose:
                            print(f"\n[Comparison {comparison_count}/{total_comparisons}]")
                            print(f"Comparing {cve1.get('cve')} ↔ {cve2.get('cve')}")

                        impact = self.analyze_patch_impact(cve1, cve2, verbose=verbose)

                        comparison = {
                            'plugin': plugin_slug,
                            'cve1': cve1.get('cve'),
                            'cve2': cve2.get('cve'),
                            'temporal_relationship': 'all-pairs',
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
                            if verbose:
                                print(f"⚠️  HIGH IMPACT DETECTED: {impact.impact_score:.2f} ({impact.impact_level})")

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

    def _sort_cves_chronologically(self,
                                   cves: List[Dict],
                                   date_field: str = None,
                                   verbose: bool = False) -> List[Dict]:
        """
        Sort CVEs in chronological order (earliest to latest).

        Args:
            cves: List of CVE data dicts
            date_field: Optional field name containing date/timestamp
            verbose: Whether to print verbose output

        Returns:
            Sorted list of CVEs
        """
        import re
        from datetime import datetime

        def get_sort_key(cve_data):
            # If date field specified and exists, use it
            if date_field and date_field in cve_data:
                date_val = cve_data[date_field]
                # Try to parse as datetime if string
                if isinstance(date_val, str):
                    try:
                        return datetime.fromisoformat(date_val.replace('Z', '+00:00'))
                    except:
                        pass
                return date_val

            # Fall back to CVE ID parsing (CVE-YYYY-NNNNN)
            cve_id = cve_data.get('cve', '')
            match = re.match(r'CVE-(\d{4})-(\d+)', cve_id, re.IGNORECASE)
            if match:
                year = int(match.group(1))
                number = int(match.group(2))
                return (year, number)

            # Last resort: use CVE string itself
            return cve_id

        try:
            sorted_cves = sorted(cves, key=get_sort_key)
            if verbose and len(cves) > 1:
                print(f"  Sorted {len(cves)} CVEs chronologically")
            return sorted_cves
        except Exception as e:
            if verbose:
                print(f"  Warning: Could not sort CVEs chronologically: {e}")
            return cves

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
