"""
Unified Dashboard UI Components for CyberShell
Combines metrics, visualizations, and UI elements for Streamlit dashboard
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import json


# ========== Metrics Display Components ==========

class MetricsDisplay:
    """Display various metrics in the dashboard"""
    
    @staticmethod
    def show_summary_metrics(data: Dict[str, Any]):
        """Display summary metrics in columns"""
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total = data.get('total_vulns', 0)
            delta = data.get('vulns_delta', 0)
            st.metric(
                "Total Vulnerabilities", 
                total,
                delta=delta if delta != 0 else None
            )
        
        with col2:
            critical = data.get('critical', 0)
            critical_delta = data.get('critical_delta', 0)
            st.metric(
                "Critical Findings", 
                critical,
                delta=critical_delta if critical_delta != 0 else None,
                delta_color="inverse"
            )
        
        with col3:
            success_rate = data.get('success_rate', 0)
            st.metric(
                "Success Rate", 
                f"{success_rate:.1%}",
                delta=f"{data.get('success_delta', 0):.1%}" if 'success_delta' in data else None
            )
        
        with col4:
            confidence = data.get('confidence', 0)
            st.metric(
                "Avg. Confidence", 
                f"{confidence:.2f}",
                help="Average confidence score across all findings"
            )
    
    @staticmethod
    def show_exploitation_metrics(results: List[Dict]):
        """Display detailed exploitation metrics"""
        if not results:
            st.info("No exploitation results to display")
            return
        
        # Create DataFrame
        df = pd.DataFrame(results)
        
        # Add formatting for specific columns if they exist
        if 'evidence_score' in df.columns:
            df['evidence_score'] = df['evidence_score'].apply(lambda x: f"{x:.2f}")
        
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.sort_values('timestamp', ascending=False)
        
        # Display with custom styling
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "evidence_score": st.column_config.ProgressColumn(
                    "Evidence Score",
                    help="Confidence in the finding",
                    min_value=0,
                    max_value=1,
                ),
                "severity": st.column_config.TextColumn(
                    "Severity",
                    help="Vulnerability severity level"
                ),
                "timestamp": st.column_config.DatetimeColumn(
                    "Time",
                    format="DD/MM/YY HH:mm"
                )
            }
        )
    
    @staticmethod
    def show_target_metrics(target_data: Dict[str, Any]):
        """Display metrics for a specific target"""
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Target", target_data.get('url', 'Unknown'))
            st.metric("Vulnerabilities Found", target_data.get('vuln_count', 0))
            st.metric("Technologies Detected", len(target_data.get('technologies', [])))
        
        with col2:
            st.metric("Risk Level", target_data.get('risk_level', 'Unknown'))
            st.metric("Last Scanned", target_data.get('last_scan', 'Never'))
            if target_data.get('waf'):
                st.warning(f"WAF Detected: {target_data['waf']}")
    
    @staticmethod
    def show_performance_metrics(perf_data: Dict[str, Any]):
        """Display performance metrics"""
        cols = st.columns(5)
        
        metrics = [
            ("Requests/sec", perf_data.get('rps', 0), "🚀"),
            ("Avg Response Time", f"{perf_data.get('avg_response_ms', 0)}ms", "⏱️"),
            ("Success Rate", f"{perf_data.get('success_rate', 0):.1%}", "✅"),
            ("Errors", perf_data.get('error_count', 0), "❌"),
            ("Uptime", f"{perf_data.get('uptime_hours', 0)}h", "🟢")
        ]
        
        for col, (label, value, icon) in zip(cols, metrics):
            with col:
                st.metric(label, f"{icon} {value}")


# ========== Visualization Components ==========

class VulnerabilityChart:
    """Vulnerability visualization charts"""
    
    @staticmethod
    def severity_distribution(data: Dict[str, int], title: str = "Vulnerability Severity Distribution"):
        """Create severity distribution pie chart"""
        if not data or all(v == 0 for v in data.values()):
            st.info("No vulnerability data to visualize")
            return None
        
        # Filter out zero values
        filtered_data = {k: v for k, v in data.items() if v > 0}
        
        fig = px.pie(
            values=list(filtered_data.values()),
            names=list(filtered_data.keys()),
            title=title,
            color_discrete_map={
                'Critical': '#d32f2f',
                'High': '#f57c00',
                'Medium': '#fbc02d',
                'Low': '#388e3c',
                'Info': '#1976d2'
            },
            hole=0.3  # Create donut chart
        )
        
        fig.update_traces(
            textposition='inside',
            textinfo='percent+label',
            hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
        )
        
        fig.update_layout(
            showlegend=True,
            legend=dict(orientation="v", yanchor="middle", y=0.5)
        )
        
        return fig
    
    @staticmethod
    def vulnerability_timeline(events: List[Dict], title: str = "Vulnerability Discovery Timeline"):
        """Create vulnerability timeline chart"""
        if not events:
            st.info("No timeline data available")
            return None
        
        # Prepare data
        df = pd.DataFrame(events)
        
        # Ensure we have required columns
        if 'timestamp' not in df.columns or 'severity' not in df.columns:
            st.warning("Timeline data missing required fields")
            return None
        
        # Convert timestamp to datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Create timeline
        fig = go.Figure()
        
        # Group by severity for different colors
        severity_colors = {
            'Critical': '#d32f2f',
            'High': '#f57c00',
            'Medium': '#fbc02d',
            'Low': '#388e3c',
            'Info': '#1976d2'
        }
        
        for severity, color in severity_colors.items():
            severity_df = df[df['severity'] == severity]
            if not severity_df.empty:
                fig.add_trace(go.Scatter(
                    x=severity_df['timestamp'],
                    y=severity_df.get('confidence', [0.5] * len(severity_df)),
                    mode='markers+text',
                    name=severity,
                    marker=dict(size=10, color=color),
                    text=severity_df.get('type', ''),
                    textposition='top center',
                    hovertemplate='<b>%{text}</b><br>Time: %{x}<br>Confidence: %{y:.2f}<extra></extra>'
                ))
        
        fig.update_layout(
            title=title,
            xaxis_title="Time",
            yaxis_title="Confidence Score",
            yaxis=dict(range=[0, 1.1]),
            hovermode='closest',
            showlegend=True
        )
        
        return fig
    
    @staticmethod
    def vulnerability_heatmap(data: List[Dict], title: str = "Vulnerability Heatmap"):
        """Create vulnerability heatmap by target and type"""
        if not data:
            st.info("No data for heatmap")
            return None
        
        # Prepare data for heatmap
        df = pd.DataFrame(data)
        
        if 'target' not in df.columns or 'vuln_type' not in df.columns:
            st.warning("Heatmap data missing required fields")
            return None
        
        # Create pivot table
        pivot = df.pivot_table(
            values='count' if 'count' in df.columns else 'evidence_score',
            index='target',
            columns='vuln_type',
            fill_value=0,
            aggfunc='sum' if 'count' in df.columns else 'mean'
        )
        
        fig = px.imshow(
            pivot,
            title=title,
            labels=dict(x="Vulnerability Type", y="Target", color="Count"),
            color_continuous_scale='RdYlGn_r',
            aspect="auto"
        )
        
        fig.update_layout(
            xaxis_title="Vulnerability Type",
            yaxis_title="Target",
            coloraxis_colorbar=dict(title="Severity")
        )
        
        return fig
    
    @staticmethod
    def vulnerability_trends(data: List[Dict], window: int = 7):
        """Create vulnerability trends over time"""
        if not data:
            st.info("No trend data available")
            return None
        
        df = pd.DataFrame(data)
        df['date'] = pd.to_datetime(df['timestamp']).dt.date
        
        # Aggregate by date and severity
        trends = df.groupby(['date', 'severity']).size().reset_index(name='count')
        
        fig = px.line(
            trends,
            x='date',
            y='count',
            color='severity',
            title=f"Vulnerability Trends ({window}-day window)",
            color_discrete_map={
                'Critical': '#d32f2f',
                'High': '#f57c00',
                'Medium': '#fbc02d',
                'Low': '#388e3c'
            }
        )
        
        fig.update_layout(
            xaxis_title="Date",
            yaxis_title="Count",
            hovermode='x unified'
        )
        
        return fig


class PerformanceGraph:
    """Performance visualization graphs"""
    
    @staticmethod
    def performance_over_time(data: List[Dict], metric: str = 'performance'):
        """Create performance over time graph"""
        if not data:
            st.info("No performance data available")
            return None
        
        df = pd.DataFrame(data)
        
        # Ensure we have required columns
        if 'timestamp' not in df.columns or metric not in df.columns:
            st.warning(f"Performance data missing required fields: timestamp, {metric}")
            return None
        
        fig = px.line(
            df,
            x='timestamp',
            y=metric,
            title=f'{metric.replace("_", " ").title()} Over Time',
            markers=True
        )
        
        # Add average line
        avg_value = df[metric].mean()
        fig.add_hline(
            y=avg_value,
            line_dash="dash",
            annotation_text=f"Average: {avg_value:.2f}",
            annotation_position="right"
        )
        
        fig.update_layout(
            xaxis_title="Time",
            yaxis_title=metric.replace("_", " ").title(),
            hovermode='x'
        )
        
        return fig
    
    @staticmethod
    def exploitation_success_rate(data: List[Dict]):
        """Create exploitation success rate chart"""
        if not data:
            st.info("No exploitation data available")
            return None
        
        df = pd.DataFrame(data)
        
        # Calculate success rate by vulnerability type
        if 'vuln_type' in df.columns and 'success' in df.columns:
            success_rates = df.groupby('vuln_type')['success'].agg(['sum', 'count'])
            success_rates['rate'] = success_rates['sum'] / success_rates['count'] * 100
            
            fig = px.bar(
                x=success_rates.index,
                y=success_rates['rate'],
                title="Exploitation Success Rate by Vulnerability Type",
                labels={'x': 'Vulnerability Type', 'y': 'Success Rate (%)'},
                color=success_rates['rate'],
                color_continuous_scale='RdYlGn',
                text=success_rates['rate'].round(1)
            )
            
            fig.update_traces(texttemplate='%{text}%', textposition='outside')
            fig.update_layout(showlegend=False)
            
            return fig
        
        return None
    
    @staticmethod
    def response_time_distribution(data: List[Dict]):
        """Create response time distribution histogram"""
        if not data:
            st.info("No response time data available")
            return None
        
        df = pd.DataFrame(data)
        
        if 'response_time' not in df.columns:
            st.warning("Response time data not available")
            return None
        
        fig = px.histogram(
            df,
            x='response_time',
            nbins=30,
            title="Response Time Distribution",
            labels={'response_time': 'Response Time (ms)', 'count': 'Frequency'}
        )
        
        # Add percentile lines
        percentiles = [50, 90, 99]
        colors = ['green', 'orange', 'red']
        
        for p, color in zip(percentiles, colors):
            value = df['response_time'].quantile(p/100)
            fig.add_vline(
                x=value,
                line_dash="dash",
                line_color=color,
                annotation_text=f"P{p}: {value:.1f}ms",
                annotation_position="top"
            )
        
        return fig
    
    @staticmethod
    def plugin_performance_matrix(data: List[Dict]):
        """Create plugin performance matrix"""
        if not data:
            st.info("No plugin performance data available")
            return None
        
        df = pd.DataFrame(data)
        
        if 'plugin' not in df.columns or 'execution_time' not in df.columns:
            st.warning("Plugin performance data incomplete")
            return None
        
        # Aggregate by plugin
        perf = df.groupby('plugin').agg({
            'execution_time': 'mean',
            'success': 'mean' if 'success' in df.columns else lambda x: 1,
            'evidence_score': 'mean' if 'evidence_score' in df.columns else lambda x: 0.5
        }).round(2)
        
        fig = go.Figure(data=go.Scatter(
            x=perf['execution_time'],
            y=perf.get('success', [1] * len(perf)) * 100,
            mode='markers+text',
            marker=dict(
                size=perf.get('evidence_score', [0.5] * len(perf)) * 50,
                color=perf.get('evidence_score', [0.5] * len(perf)),
                colorscale='RdYlGn',
                showscale=True,
                colorbar=dict(title="Evidence Score")
            ),
            text=perf.index,
            textposition='top center',
            hovertemplate='<b>%{text}</b><br>Execution Time: %{x:.1f}ms<br>Success Rate: %{y:.1f}%<extra></extra>'
        ))
        
        fig.update_layout(
            title="Plugin Performance Matrix",
            xaxis_title="Avg Execution Time (ms)",
            yaxis_title="Success Rate (%)",
            yaxis=dict(range=[0, 105])
        )
        
        return fig


# ========== Interactive Components ==========

class InteractiveControls:
    """Interactive control elements for the dashboard"""
    
    @staticmethod
    def target_selector(targets: List[str]) -> str:
        """Create target selector dropdown"""
        return st.selectbox(
            "Select Target",
            targets,
            help="Choose a target to view details"
        )
    
    @staticmethod
    def date_range_selector(default_days: int = 7) -> Tuple[datetime, datetime]:
        """Create date range selector"""
        col1, col2 = st.columns(2)
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=default_days)
        
        with col1:
            start = st.date_input("Start Date", start_date)
        
        with col2:
            end = st.date_input("End Date", end_date)
        
        return start, end
    
    @staticmethod
    def severity_filter() -> List[str]:
        """Create severity filter checkboxes"""
        severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
        selected = st.multiselect(
            "Filter by Severity",
            severities,
            default=severities[:3],  # Default to Critical, High, Medium
            help="Select which severity levels to display"
        )
        return selected
    
    @staticmethod
    def refresh_button(key: str = "refresh") -> bool:
        """Create refresh button"""
        return st.button("🔄 Refresh", key=key, help="Refresh the data")
    
    @staticmethod
    def export_button(data: Any, filename: str = "export.json", key: str = "export"):
        """Create export button for data"""
        if st.button(f"📥 Export Data", key=key):
            if isinstance(data, pd.DataFrame):
                csv = data.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=filename.replace('.json', '.csv'),
                    mime="text/csv"
                )
            else:
                json_str = json.dumps(data, indent=2, default=str)
                st.download_button(
                    label="Download JSON",
                    data=json_str,
                    file_name=filename,
                    mime="application/json"
                )


# ========== Layout Components ==========

class DashboardLayout:
    """Dashboard layout helper components"""
    
    @staticmethod
    def create_header(title: str, subtitle: str = None):
        """Create dashboard header"""
        st.title(title)
        if subtitle:
            st.markdown(f"*{subtitle}*")
        st.divider()
    
    @staticmethod
    def create_tabs(tab_names: List[str]) -> List:
        """Create dashboard tabs"""
        return st.tabs(tab_names)
    
    @staticmethod
    def create_sidebar_filters() -> Dict[str, Any]:
        """Create sidebar filters"""
        filters = {}
        
        with st.sidebar:
            st.header("Filters")
            
            filters['severity'] = InteractiveControls.severity_filter()
            
            st.divider()
            
            filters['date_range'] = InteractiveControls.date_range_selector()
            
            st.divider()
            
            filters['show_failed'] = st.checkbox(
                "Show Failed Attempts",
                value=False,
                help="Include failed exploitation attempts"
            )
            
            filters['confidence_threshold'] = st.slider(
                "Min Confidence Score",
                0.0, 1.0, 0.5,
                help="Minimum confidence threshold for results"
            )
        
        return filters
    
    @staticmethod
    def create_status_indicator(status: str):
        """Create status indicator with color"""
        status_colors = {
            'running': '🟢',
            'stopped': '🔴',
            'paused': '🟡',
            'error': '❌'
        }
        
        icon = status_colors.get(status.lower(), '⚪')
        st.markdown(f"{icon} **Status:** {status.upper()}")
    
    @staticmethod
    def create_progress_indicator(current: int, total: int, label: str = "Progress"):
        """Create progress indicator"""
        if total > 0:
            progress = current / total
            st.progress(progress, text=f"{label}: {current}/{total} ({progress:.1%})")
        else:
            st.progress(0, text=f"{label}: 0/0")


# ========== Composite Components ==========

class DashboardComponents:
    """High-level dashboard components combining multiple elements"""
    
    @staticmethod
    def vulnerability_overview(data: Dict[str, Any]):
        """Create complete vulnerability overview section"""
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Severity distribution
            if 'severity_counts' in data:
                fig = VulnerabilityChart.severity_distribution(data['severity_counts'])
                if fig:
                    st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Summary metrics
            st.subheader("Summary")
            MetricsDisplay.show_summary_metrics(data)
            
            # Top vulnerabilities
            if 'top_vulns' in data:
                st.subheader("Top Findings")
                for vuln in data['top_vulns'][:5]:
                    st.write(f"• {vuln['type']} ({vuln['severity']})")
    
    @staticmethod
    def exploitation_dashboard(results: List[Dict], filters: Dict[str, Any] = None):
        """Create exploitation results dashboard"""
        if filters:
            # Apply filters
            df = pd.DataFrame(results)
            
            if 'severity' in filters and filters['severity']:
                df = df[df['severity'].isin(filters['severity'])]
            
            if 'confidence_threshold' in filters:
                df = df[df['evidence_score'] >= filters['confidence_threshold']]
            
            if not filters.get('show_failed', False):
                df = df[df['success'] == True]
            
            results = df.to_dict('records')
        
        # Display metrics
        st.subheader("Exploitation Results")
        MetricsDisplay.show_exploitation_metrics(results)
        
        # Success rate chart
        if results:
            fig = PerformanceGraph.exploitation_success_rate(results)
            if fig:
                st.plotly_chart(fig, use_container_width=True)
    
    @staticmethod
    def performance_monitor(perf_data: List[Dict]):
        """Create performance monitoring section"""
        tab1, tab2, tab3 = st.tabs(["Overview", "Response Times", "Plugin Performance"])
        
        with tab1:
            if perf_data:
                latest = perf_data[-1] if perf_data else {}
                MetricsDisplay.show_performance_metrics(latest)
                
                fig = PerformanceGraph.performance_over_time(perf_data)
                if fig:
                    st.plotly_chart(fig, use_container_width=True)
        
        with tab2:
            fig = PerformanceGraph.response_time_distribution(perf_data)
            if fig:
                st.plotly_chart(fig, use_container_width=True)
        
        with tab3:
            fig = PerformanceGraph.plugin_performance_matrix(perf_data)
            if fig:
                st.plotly_chart(fig, use_container_width=True)


# ========== Convenience Functions ==========

def create_dashboard(title: str = "CyberShell Dashboard") -> Dict[str, Any]:
    """Create and return dashboard components"""
    
    # Set page config
    st.set_page_config(
        page_title=title,
        page_icon="🛡️",
        layout="wide"
    )
    
    # Create header
    DashboardLayout.create_header(title, "Autonomous Exploitation Framework")
    
    # Create sidebar filters
    filters = DashboardLayout.create_sidebar_filters()
    
    # Return components for use
    return {
        'metrics': MetricsDisplay(),
        'charts': VulnerabilityChart(),
        'graphs': PerformanceGraph(),
        'controls': InteractiveControls(),
        'layout': DashboardLayout(),
        'components': DashboardComponents(),
        'filters': filters
    }


# Backward compatibility exports
MetricsDisplay = MetricsDisplay
VulnerabilityChart = VulnerabilityChart
PerformanceGraph = PerformanceGraph
