/**
 * Data loader for benchmark report pages.
 * Loads and provides access to benchmark-data.json
 */
class BenchmarkDataLoader {
    constructor() {
        this.data = null;
        this.loadPromise = null;
    }

    /**
     * Loads the benchmark data JSON file.
     * @returns {Promise<Object>} Promise resolving to the data object
     */
    async loadData() {
        if (this.data) {
            return this.data;
        }

        if (!this.loadPromise) {
            this.loadPromise = fetch('data/benchmark-data.json')
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`Failed to load benchmark data: ${response.statusText}`);
                    }
                    return response.json();
                })
                .then(data => {
                    this.data = data;
                    return data;
                })
                .catch(error => {
                    console.error('Error loading benchmark data:', error);
                    // Return empty structure on error
                    return {
                        metadata: {},
                        overview: {},
                        benchmarks: [],
                        chartData: {},
                        trends: {}
                    };
                });
        }

        return this.loadPromise;
    }

    /**
     * Renders the overview section with data from JSON.
     */
    async renderOverview() {
        const data = await this.loadData();
        const overview = data.overview || {};
        
        // Update overview elements
        const elements = {
            'performance-score': overview.performanceScore !== undefined ? overview.performanceScore : 'N/A',
            'performance-grade': overview.performanceGrade || 'N/A',
            'throughput': overview.throughput || 'N/A',
            'latency': overview.latency || 'N/A',
            'throughput-name': overview.throughputBenchmarkName ? `(${overview.throughputBenchmarkName})` : '',
            'latency-name': overview.latencyBenchmarkName ? `(${overview.latencyBenchmarkName})` : ''
        };

        for (const [id, value] of Object.entries(elements)) {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
                
                // Add grade class styling
                if (id === 'performance-grade' && overview.performanceGradeClass) {
                    element.className = 'stat-value grade ' + overview.performanceGradeClass;
                }
            }
        }

        // Update timestamp if present
        const timestampElement = document.getElementById('report-timestamp');
        if (timestampElement && data.metadata?.displayTimestamp) {
            timestampElement.textContent = data.metadata.displayTimestamp;
        }

        // Update benchmark type in title if present
        const titleElement = document.getElementById('benchmark-type-title');
        if (titleElement && data.metadata?.benchmarkType) {
            titleElement.textContent = data.metadata.benchmarkType;
        }
    }

    /**
     * Renders the benchmark results as a horizontal bar chart.
     */
    async renderBenchmarkResultsChart() {
        const data = await this.loadData();
        const benchmarks = data.benchmarks || [];
        const canvas = document.getElementById('benchmark-results-chart');
        
        if (!canvas || !window.Chart) return;

        const ctx = canvas.getContext('2d');
        
        // Separate throughput and latency benchmarks
        const throughputBenchmarks = benchmarks.filter(b => b.throughput);
        const latencyBenchmarks = benchmarks.filter(b => b.latency);
        
        // Prepare data for combined display
        const labels = benchmarks.map(b => b.name);
        const values = [];
        const backgroundColors = [];
        const borderColors = [];
        
        benchmarks.forEach(benchmark => {
            if (benchmark.throughput) {
                // Normalize throughput to a 0-100 scale for display
                const normalizedValue = (benchmark.throughput / 1000); // Convert to K ops/s
                values.push(normalizedValue);
                backgroundColors.push('rgba(54, 162, 235, 0.8)');
                borderColors.push('rgba(54, 162, 235, 1)');
            } else if (benchmark.latency) {
                // Show latency directly (already in ms)
                values.push(benchmark.latency * 100); // Scale up for visibility
                backgroundColors.push('rgba(255, 99, 132, 0.8)');
                borderColors.push('rgba(255, 99, 132, 1)');
            }
        });

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Performance',
                    data: values,
                    backgroundColor: backgroundColors,
                    borderColor: borderColors,
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y', // Horizontal bar chart
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const index = context.dataIndex;
                                const benchmark = benchmarks[index];
                                if (benchmark.throughput) {
                                    return `Throughput: ${benchmark.throughput}`;
                                } else if (benchmark.latency) {
                                    return `Latency: ${benchmark.latency}`;
                                }
                                return benchmark.score;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: 'Performance (Throughput in K ops/s, Latency scaled x100)'
                        },
                        ticks: {
                            callback: function(value) {
                                return value.toFixed(0);
                            }
                        }
                    }
                }
            }
        });
    }

    /**
     * Renders the percentiles chart as a grouped bar chart
     * @param {string} canvasId - The ID of the canvas element 
     */
    async renderPercentilesChart(canvasId) {
        const data = await this.loadData();
        const chartData = data.chartData || {};
        const percentilesData = chartData.percentilesData || {};
        const canvas = document.getElementById(canvasId);

        if (!canvas || !window.Chart) return;

        const ctx = canvas.getContext('2d');

        // Always use linear scale starting at zero for percentile distribution charts.
        // Percentile data spans a narrow range (e.g. 1.9-2.4ms) where logarithmic
        // scale distorts the visual representation.

        // Create datasets for each percentile level
        const percentileLabels = percentilesData.percentileLabels || [];
        const benchmarks = percentilesData.benchmarks || [];
        const dataByBenchmark = percentilesData.data || {};
        
        const datasets = [];
        const colors = [
            'rgba(54, 162, 235, 0.8)',   // Blue
            'rgba(255, 99, 132, 0.8)',   // Red
            'rgba(75, 192, 192, 0.8)',   // Green
            'rgba(255, 206, 86, 0.8)',   // Yellow
            'rgba(153, 102, 255, 0.8)',  // Purple
            'rgba(255, 159, 64, 0.8)'    // Orange
        ];
        
        let colorIndex = 0;
        for (const [benchmark, values] of Object.entries(dataByBenchmark)) {
            datasets.push({
                label: benchmark,
                data: values,
                backgroundColor: colors[colorIndex % colors.length],
                borderColor: colors[colorIndex % colors.length].replace('0.8', '1'),
                borderWidth: 1
            });
            colorIndex++;
        }
        
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: percentileLabels,
                datasets: datasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Latency Distribution Across Percentiles'
                    },
                    legend: {
                        display: true,
                        position: 'top'
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                scales: {
                    x: {
                        display: true,
                        title: {
                            display: true,
                            text: 'Percentile'
                        }
                    },
                    y: {
                        display: true,
                        title: {
                            display: true,
                            text: 'Latency (ms/op)'
                        },
                        type: 'linear',
                        beginAtZero: true,
                        ticks: {
                            callback: function(value) {
                                if (value >= 1000) {
                                    return (value/1000) + 's';
                                } else if (value >= 1) {
                                    return value + 'ms';
                                } else {
                                    return (value * 1000) + 'μs';
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    /**
     * Renders charts using the chart data from JSON.
     * @param {string} canvasId - The ID of the canvas element
     * @param {string} chartType - Type of chart to render ('overview', 'trends', 'detailed')
     */
    async renderChart(canvasId, chartType = 'overview') {
        const data = await this.loadData();
        const chartData = data.chartData || {};
        const canvas = document.getElementById(canvasId);
        
        if (!canvas || !window.Chart) return;

        const ctx = canvas.getContext('2d');
        
        let config;
        switch (chartType) {
            case 'overview':
                config = this.createOverviewChartConfig(chartData);
                break;
            case 'trends':
                config = this.createTrendsChartConfig(data.trends);
                break;
            case 'detailed':
                config = this.createDetailedChartConfig(chartData);
                break;
            default:
                config = this.createOverviewChartConfig(chartData);
        }

        new Chart(ctx, config);
    }

    /**
     * Creates configuration for the overview chart.
     */
    createOverviewChartConfig(chartData) {
        return {
            type: 'bar',
            data: {
                labels: chartData.labels || [],
                datasets: [{
                    label: 'Throughput (ops/s)',
                    data: chartData.throughput || [],
                    backgroundColor: 'rgba(75, 192, 192, 0.6)',
                    borderColor: 'rgba(75, 192, 192, 1)',
                    borderWidth: 1,
                    yAxisID: 'y-throughput'
                }, {
                    label: 'Latency (ms/op)',
                    data: chartData.latency || [],
                    backgroundColor: 'rgba(255, 99, 132, 0.6)',
                    borderColor: 'rgba(255, 99, 132, 1)',
                    borderWidth: 1,
                    yAxisID: 'y-latency'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Benchmark Performance Overview'
                    },
                    legend: {
                        display: true,
                        position: 'top'
                    }
                },
                scales: {
                    'y-throughput': {
                        type: 'linear',
                        display: true,
                        position: 'left',
                        title: {
                            display: true,
                            text: 'Throughput (ops/s)'
                        }
                    },
                    'y-latency': {
                        type: 'linear',
                        display: true,
                        position: 'right',
                        title: {
                            display: true,
                            text: 'Latency (ms/op)'
                        },
                        grid: {
                            drawOnChartArea: false
                        }
                    }
                }
            }
        };
    }

    /**
     * Creates configuration for the trends chart.
     */
    createTrendsChartConfig(trendData) {
        if (!trendData?.available) {
            return this.createNoDataChartConfig();
        }
        
        const chartData = trendData.chartData || {};
        const timestamps = chartData.timestamps || [];
        const throughputValues = chartData.throughput || [];
        const latencyValues = chartData.latency || [];
        const performanceScores = chartData.performanceScores || [];
        
        // Format timestamps for display
        const labels = timestamps.map(ts => {
            if (ts === 'Current') return ts;
            try {
                return new Date(ts).toLocaleDateString('en-US', { 
                    month: 'short', 
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit'
                });
            } catch {
                return ts;
            }
        });

        return {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Throughput (ops/s)',
                    data: throughputValues,
                    borderColor: 'rgb(75, 192, 192)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    yAxisID: 'y-throughput',
                    tension: 0.1
                }, {
                    label: 'Latency (ms/op)',
                    data: latencyValues,
                    borderColor: 'rgb(255, 99, 132)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    yAxisID: 'y-latency',
                    tension: 0.1
                }, {
                    label: 'Performance Score',
                    data: performanceScores,
                    borderColor: 'rgb(54, 162, 235)',
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    yAxisID: 'y-score',
                    tension: 0.1,
                    hidden: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Performance Trends Over Time'
                    },
                    tooltip: {
                        callbacks: {
                            afterLabel: function(context) {
                                if (context.dataset.label === 'Performance Score') {
                                    return `Grade: ${getGradeFromScore(context.parsed.y)}`;
                                }
                                return '';
                            }
                        }
                    },
                    legend: {
                        display: true,
                        position: 'top'
                    }
                },
                scales: {
                    x: {
                        display: true,
                        title: {
                            display: true,
                            text: 'Benchmark Run'
                        }
                    },
                    'y-throughput': {
                        type: 'linear',
                        display: true,
                        position: 'left',
                        title: {
                            display: true,
                            text: 'Throughput (ops/s)'
                        },
                        ticks: {
                            callback: function(value) {
                                if (value >= 1000000) {
                                    return (value / 1000000).toFixed(1) + 'M';
                                } else if (value >= 1000) {
                                    return (value / 1000).toFixed(1) + 'K';
                                }
                                return value;
                            }
                        }
                    },
                    'y-latency': {
                        type: 'linear',
                        display: true,
                        position: 'right',
                        title: {
                            display: true,
                            text: 'Latency (ms/op)'
                        },
                        grid: {
                            drawOnChartArea: false
                        }
                    },
                    'y-score': {
                        type: 'linear',
                        display: false,
                        position: 'right',
                        min: 0,
                        max: 100,
                        title: {
                            display: true,
                            text: 'Score'
                        }
                    }
                }
            }
        };
        
        function getGradeFromScore(score) {
            if (score >= 95) return 'A+';
            if (score >= 85) return 'A';
            if (score >= 75) return 'B';
            if (score >= 65) return 'C';
            if (score >= 55) return 'D';
            return 'F';
        }
    }
    
    /**
     * Creates a chart configuration for when no data is available.
     */
    createNoDataChartConfig() {
        return {
            type: 'line',
            data: {
                labels: ['No historical data available'],
                datasets: [{
                    label: 'No Data',
                    data: [0],
                    borderColor: 'rgba(200, 200, 200, 0.5)',
                    backgroundColor: 'rgba(200, 200, 200, 0.1)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Performance Trends (No Historical Data)'
                    },
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 1
                    }
                }
            }
        };
    }

    /**
     * Creates configuration for the detailed chart.
     */
    createDetailedChartConfig(chartData) {
        return {
            type: 'radar',
            data: {
                labels: chartData.labels || [],
                datasets: [{
                    label: 'Performance Score',
                    data: (chartData.throughput || []).map(val => Math.min(100, val / 1000)),
                    borderColor: 'rgb(54, 162, 235)',
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    pointBackgroundColor: 'rgb(54, 162, 235)',
                    pointBorderColor: '#fff',
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: 'rgb(54, 162, 235)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Detailed Performance Analysis'
                    }
                },
                scales: {
                    r: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            stepSize: 20
                        }
                    }
                }
            }
        };
    }

    /**
     * Renders the trends table with benchmark comparisons.
     */
    async renderTrendsTable() {
        const data = await this.loadData();
        const benchmarks = data.benchmarks || [];
        const tableBody = document.getElementById('trends-table-body');
        
        if (!tableBody) return;

        tableBody.innerHTML = '';
        
        benchmarks.forEach(benchmark => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${benchmark.name}</td>
                <td>${benchmark.scoreFormatted}</td>
                <td>N/A</td>
                <td>-</td>
            `;
            tableBody.appendChild(row);
        });
    }

    /**
     * Renders the trend summary text below the chart.
     */
    async renderTrendSummary() {
        const data = await this.loadData();
        const trends = data.trends || {};
        const summaryDiv = document.querySelector('.trends-summary');

        if (!summaryDiv) return;

        // Add trend summary if available
        if (trends.summary) {
            // Check if summary paragraph already exists
            const existingSummary = summaryDiv.querySelector('.trend-summary-text');
            if (!existingSummary) {
                const summaryPara = document.createElement('p');
                summaryPara.className = 'trend-summary-text';
                summaryPara.innerHTML = `<strong>Trend:</strong> ${trends.summary}`;
                summaryDiv.appendChild(summaryPara);
            }
        }
    }

    /**
     * Loads the JMH Visualizer in an iframe
     */
    loadJMHVisualizer() {
        const iframe = document.getElementById('jmh-visualizer-frame');
        const errorDiv = document.getElementById('visualizer-error');
        
        if (!iframe) return;
        
        // Get the base URL of the current page
        const baseUrl = window.location.href.split('/').slice(0, -1).join('/');
        const jsonUrl = baseUrl + '/data/original-jmh-result.json';
        
        // Check if the JSON file exists
        fetch(jsonUrl, { method: 'HEAD' })
            .then(response => {
                if (response.ok) {
                    // Load JMH Visualizer with the JSON file URL
                    iframe.src = 'https://jmh.morethan.io/?source=' + encodeURIComponent(jsonUrl);
                    iframe.style.display = 'block';
                    if (errorDiv) errorDiv.style.display = 'none';
                    
                    // Add timeout fallback
                    let iframeLoaded = false;
                    
                    iframe.addEventListener('load', function() {
                        iframeLoaded = true;
                    });
                    
                    // If iframe doesn't load in 10 seconds, show error
                    setTimeout(() => {
                        if (!iframeLoaded && errorDiv) {
                            iframe.style.display = 'none';
                            errorDiv.style.display = 'block';
                        }
                    }, 10000);
                } else {
                    // JSON file not found, show error
                    iframe.style.display = 'none';
                    if (errorDiv) errorDiv.style.display = 'block';
                }
            })
            .catch(() => {
                // Error checking file, show error
                iframe.style.display = 'none';
                if (errorDiv) errorDiv.style.display = 'block';
            });
    }

    /**
     * Updates all page elements based on the current page type.
     * @param {string} pageType - Type of page ('index', 'trends', 'detailed')
     */
    async updatePage(pageType = 'index') {
        try {
            switch (pageType) {
                case 'index':
                    await this.renderOverview();
                    await this.renderChart('overview-chart', 'overview');
                    await this.renderPercentilesChart('percentiles-chart');
                    break;
                case 'trends':
                    await this.renderOverview();
                    await this.renderChart('trends-chart', 'trends');
                    await this.renderTrendSummary();
                    break;
                case 'detailed':
                    await this.renderOverview();
                    this.loadJMHVisualizer();
                    break;
            }
        } catch (error) {
            console.error('Error updating page:', error);
        }
    }
}

// Create global instance
const benchmarkLoader = new BenchmarkDataLoader();

// Adjust navigation based on benchmark type
function adjustNavigationForBenchmarkType(data) {
    const benchmarkType = data.metadata?.benchmarkType?.toLowerCase() || '';

    // Hide 'Detailed' nav link for non-micro benchmarks (no JMH data available)
    if (!benchmarkType.includes('micro')) {
        const detailedLink = document.querySelector('a.nav-link[href="detailed.html"]');
        if (detailedLink) detailedLink.style.display = 'none';
    }

    // Hide the current benchmark type link (only show link to the OTHER type)
    // On Micro pages: hide Micro link, show Integration link
    // On Integration pages: hide Integration link, show Micro link
    if (benchmarkType.includes('micro')) {
        const microLink = document.querySelector('a.nav-link[href="../micro/index.html"]');
        if (microLink) microLink.style.display = 'none';
    } else if (benchmarkType.includes('integration')) {
        const integrationLink = document.querySelector('a.nav-link[href="../integration/index.html"]');
        if (integrationLink) integrationLink.style.display = 'none';
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        const pageType = document.body.dataset.pageType || 'index';
        benchmarkLoader.updatePage(pageType);
        benchmarkLoader.loadData().then(adjustNavigationForBenchmarkType);
    });
} else {
    const pageType = document.body.dataset.pageType || 'index';
    benchmarkLoader.updatePage(pageType);
    benchmarkLoader.loadData().then(adjustNavigationForBenchmarkType);
}