import axios from 'axios';
import https from 'https';

interface TechnologyResult {
    name: string;
    type: string;
    confidence: string;
    version?: string;
    categories?: string[];
}

interface DetectionResult {
    technologies: TechnologyResult[];
    url: string;
    detectionTime: string;
}

// Technology signatures for detection
const TECHNOLOGY_SIGNATURES = {
    // Web Servers
    webServers: [
        { pattern: /apache/i, name: 'Apache', type: 'Web Server' },
        { pattern: /nginx/i, name: 'Nginx', type: 'Web Server' },
        { pattern: /microsoft-iis/i, name: 'Microsoft IIS', type: 'Web Server' },
        { pattern: /iis/i, name: 'Microsoft IIS', type: 'Web Server' },
        { pattern: /litespeed/i, name: 'LiteSpeed', type: 'Web Server' },
        { pattern: /cloudflare/i, name: 'Cloudflare', type: 'CDN' },
        { pattern: /openresty/i, name: 'OpenResty', type: 'Web Server' },
        { pattern: /tomcat/i, name: 'Apache Tomcat', type: 'Application Server' },
        { pattern: /jetty/i, name: 'Jetty', type: 'Application Server' },
        { pattern: /gunicorn/i, name: 'Gunicorn', type: 'Web Server' },
        { pattern: /uvicorn/i, name: 'Uvicorn', type: 'Web Server' },
        { pattern: /kestrel/i, name: 'Kestrel', type: 'Web Server' },
    ],

    // Programming Languages & Backend Frameworks
    languages: [
        // PHP
        { pattern: /php/i, name: 'PHP', type: 'Programming Language', versionPattern: /php\/?([\d.]+)/i },
        { pattern: /laravel/i, name: 'Laravel', type: 'PHP Framework', versionPattern: null },
        { pattern: /symfony/i, name: 'Symfony', type: 'PHP Framework', versionPattern: null },
        { pattern: /codeigniter/i, name: 'CodeIgniter', type: 'PHP Framework', versionPattern: null },
        { pattern: /yii/i, name: 'Yii', type: 'PHP Framework', versionPattern: null },
        { pattern: /cakephp/i, name: 'CakePHP', type: 'PHP Framework', versionPattern: null },

        // .NET / C#
        { pattern: /asp\.net\s*core/i, name: 'ASP.NET Core', type: '.NET Framework', versionPattern: null },
        { pattern: /asp\.net\s*mvc/i, name: 'ASP.NET MVC', type: '.NET Framework', versionPattern: null },
        { pattern: /asp\.net/i, name: 'ASP.NET', type: '.NET Framework', versionPattern: null },
        { pattern: /\.net\s*core/i, name: '.NET Core', type: '.NET Runtime', versionPattern: null },
        { pattern: /\.net\s*framework/i, name: '.NET Framework', type: '.NET Runtime', versionPattern: null },
        { pattern: /blazor/i, name: 'Blazor', type: '.NET Framework', versionPattern: null },
        { pattern: /signalr/i, name: 'SignalR', type: '.NET Real-time', versionPattern: null },
        { pattern: /entity\s*framework/i, name: 'Entity Framework', type: '.NET ORM', versionPattern: null },

        // Java
        { pattern: /java/i, name: 'Java', type: 'Programming Language', versionPattern: null },
        { pattern: /spring\s*boot/i, name: 'Spring Boot', type: 'Java Framework', versionPattern: null },
        { pattern: /spring\s*framework/i, name: 'Spring Framework', type: 'Java Framework', versionPattern: null },
        { pattern: /spring\s*mvc/i, name: 'Spring MVC', type: 'Java Framework', versionPattern: null },
        { pattern: /hibernate/i, name: 'Hibernate', type: 'Java ORM', versionPattern: null },
        { pattern: /struts/i, name: 'Apache Struts', type: 'Java Framework', versionPattern: null },
        { pattern: /jsf|javaserver\s*faces/i, name: 'JavaServer Faces', type: 'Java Framework', versionPattern: null },
        { pattern: /wicket/i, name: 'Apache Wicket', type: 'Java Framework', versionPattern: null },
        { pattern: /vaadin/i, name: 'Vaadin', type: 'Java Framework', versionPattern: null },
        { pattern: /grails/i, name: 'Grails', type: 'Java/Groovy Framework', versionPattern: null },
        { pattern: /quarkus/i, name: 'Quarkus', type: 'Java Framework', versionPattern: null },
        { pattern: /micronaut/i, name: 'Micronaut', type: 'Java Framework', versionPattern: null },

        // Python
        { pattern: /python/i, name: 'Python', type: 'Programming Language', versionPattern: null },
        { pattern: /django/i, name: 'Django', type: 'Python Framework', versionPattern: null },
        { pattern: /flask/i, name: 'Flask', type: 'Python Framework', versionPattern: null },
        { pattern: /fastapi/i, name: 'FastAPI', type: 'Python Framework', versionPattern: null },
        { pattern: /tornado/i, name: 'Tornado', type: 'Python Framework', versionPattern: null },
        { pattern: /pyramid/i, name: 'Pyramid', type: 'Python Framework', versionPattern: null },

        // Ruby
        { pattern: /ruby/i, name: 'Ruby', type: 'Programming Language', versionPattern: null },
        { pattern: /rails|ruby\s*on\s*rails/i, name: 'Ruby on Rails', type: 'Ruby Framework', versionPattern: null },
        { pattern: /sinatra/i, name: 'Sinatra', type: 'Ruby Framework', versionPattern: null },

        // Node.js
        { pattern: /node\.?js/i, name: 'Node.js', type: 'JavaScript Runtime', versionPattern: null },
        { pattern: /express/i, name: 'Express.js', type: 'Node.js Framework', versionPattern: null },
        { pattern: /koa/i, name: 'Koa', type: 'Node.js Framework', versionPattern: null },
        { pattern: /fastify/i, name: 'Fastify', type: 'Node.js Framework', versionPattern: null },
        { pattern: /nest\.?js|nestjs/i, name: 'NestJS', type: 'Node.js Framework', versionPattern: null },
        { pattern: /hapi/i, name: 'Hapi', type: 'Node.js Framework', versionPattern: null },

        // Go
        { pattern: /golang|go\s*http/i, name: 'Go', type: 'Programming Language', versionPattern: null },
        { pattern: /gin/i, name: 'Gin', type: 'Go Framework', versionPattern: null },
        { pattern: /echo/i, name: 'Echo', type: 'Go Framework', versionPattern: null },
        { pattern: /fiber/i, name: 'Fiber', type: 'Go Framework', versionPattern: null },

        // Rust
        { pattern: /rust/i, name: 'Rust', type: 'Programming Language', versionPattern: null },
        { pattern: /actix/i, name: 'Actix', type: 'Rust Framework', versionPattern: null },
        { pattern: /rocket/i, name: 'Rocket', type: 'Rust Framework', versionPattern: null },
    ],

    // HTML Content Patterns
    htmlPatterns: [
        // CMS
        { pattern: /wp-content|wp-includes|wordpress/i, name: 'WordPress', type: 'CMS', confidence: 'High' },
        { pattern: /joomla/i, name: 'Joomla', type: 'CMS', confidence: 'High' },
        { pattern: /drupal/i, name: 'Drupal', type: 'CMS', confidence: 'High' },
        { pattern: /typo3/i, name: 'TYPO3', type: 'CMS', confidence: 'Medium' },
        { pattern: /modx/i, name: 'MODX', type: 'CMS', confidence: 'Medium' },
        { pattern: /magento/i, name: 'Magento', type: 'E-commerce', confidence: 'High' },
        { pattern: /shopify/i, name: 'Shopify', type: 'E-commerce', confidence: 'High' },
        { pattern: /woocommerce/i, name: 'WooCommerce', type: 'E-commerce', confidence: 'High' },
        { pattern: /prestashop/i, name: 'PrestaShop', type: 'E-commerce', confidence: 'High' },

        // JavaScript Frameworks
        { pattern: /__NEXT_DATA__|_next\/static/i, name: 'Next.js', type: 'JavaScript Framework', confidence: 'High' },
        { pattern: /nuxt|__NUXT__/i, name: 'Nuxt.js', type: 'JavaScript Framework', confidence: 'High' },
        { pattern: /react|__react|reactDOM/i, name: 'React', type: 'JavaScript Framework', confidence: 'Medium' },
        { pattern: /ng-app|ng-controller|angular/i, name: 'Angular', type: 'JavaScript Framework', confidence: 'High' },
        { pattern: /vue\.js|v-bind|v-model|v-if/i, name: 'Vue.js', type: 'JavaScript Framework', confidence: 'High' },
        { pattern: /svelte/i, name: 'Svelte', type: 'JavaScript Framework', confidence: 'Medium' },
        { pattern: /ember/i, name: 'Ember.js', type: 'JavaScript Framework', confidence: 'Medium' },
        { pattern: /backbone/i, name: 'Backbone.js', type: 'JavaScript Framework', confidence: 'Medium' },

        // JavaScript Libraries
        { pattern: /jquery|jQuery/i, name: 'jQuery', type: 'JavaScript Library', confidence: 'High' },
        { pattern: /lodash/i, name: 'Lodash', type: 'JavaScript Library', confidence: 'Medium' },
        { pattern: /underscore/i, name: 'Underscore.js', type: 'JavaScript Library', confidence: 'Medium' },
        { pattern: /axios/i, name: 'Axios', type: 'JavaScript Library', confidence: 'Medium' },
        { pattern: /moment\.js|moment\(/i, name: 'Moment.js', type: 'JavaScript Library', confidence: 'Medium' },
        { pattern: /gsap|TweenMax|TweenLite/i, name: 'GSAP', type: 'JavaScript Library', confidence: 'High' },
        { pattern: /three\.js|THREE\./i, name: 'Three.js', type: 'JavaScript Library', confidence: 'High' },
        { pattern: /d3\.js|d3\./i, name: 'D3.js', type: 'JavaScript Library', confidence: 'High' },
        { pattern: /chart\.js|Chart\(/i, name: 'Chart.js', type: 'JavaScript Library', confidence: 'High' },

        // UI Frameworks
        { pattern: /bootstrap/i, name: 'Bootstrap', type: 'UI Framework', confidence: 'High' },
        { pattern: /tailwindcss|tailwind/i, name: 'Tailwind CSS', type: 'UI Framework', confidence: 'High' },
        { pattern: /bulma/i, name: 'Bulma', type: 'UI Framework', confidence: 'Medium' },
        { pattern: /foundation/i, name: 'Foundation', type: 'UI Framework', confidence: 'Medium' },
        { pattern: /materialize/i, name: 'Materialize', type: 'UI Framework', confidence: 'Medium' },
        { pattern: /semantic-ui|semantic\.min/i, name: 'Semantic UI', type: 'UI Framework', confidence: 'Medium' },
        { pattern: /antd|ant-design/i, name: 'Ant Design', type: 'UI Framework', confidence: 'High' },
        { pattern: /material-ui|@mui/i, name: 'Material-UI', type: 'UI Framework', confidence: 'High' },
        { pattern: /primereact|primeng|primevue/i, name: 'PrimeNG/React/Vue', type: 'UI Framework', confidence: 'High' },

        // Analytics
        { pattern: /google-analytics|gtag|ga\(/i, name: 'Google Analytics', type: 'Analytics', confidence: 'High' },
        { pattern: /googletagmanager/i, name: 'Google Tag Manager', type: 'Analytics', confidence: 'High' },
        { pattern: /matomo|piwik/i, name: 'Matomo', type: 'Analytics', confidence: 'High' },
        { pattern: /hotjar/i, name: 'Hotjar', type: 'Analytics', confidence: 'High' },
        { pattern: /mixpanel/i, name: 'Mixpanel', type: 'Analytics', confidence: 'High' },
        { pattern: /yandex.*metrica/i, name: 'Yandex Metrica', type: 'Analytics', confidence: 'High' },

        // Fonts
        { pattern: /fonts\.googleapis\.com/i, name: 'Google Fonts', type: 'Font', confidence: 'High' },
        { pattern: /use\.typekit\.net/i, name: 'Adobe Fonts', type: 'Font', confidence: 'High' },
        { pattern: /fontawesome|font-awesome/i, name: 'Font Awesome', type: 'Icon Library', confidence: 'High' },

        // Security
        { pattern: /recaptcha/i, name: 'reCAPTCHA', type: 'Security', confidence: 'High' },
        { pattern: /hcaptcha/i, name: 'hCaptcha', type: 'Security', confidence: 'High' },
        { pattern: /cloudflare/i, name: 'Cloudflare', type: 'CDN/Security', confidence: 'High' },

        // Build Tools
        { pattern: /webpack/i, name: 'Webpack', type: 'Build Tool', confidence: 'Medium' },
        { pattern: /vite/i, name: 'Vite', type: 'Build Tool', confidence: 'Medium' },
        { pattern: /parcel/i, name: 'Parcel', type: 'Build Tool', confidence: 'Medium' },

        // .NET / C# / ASP.NET
        { pattern: /_blazor|blazor\.server|blazor\.webassembly/i, name: 'Blazor', type: '.NET Framework', confidence: 'High' },
        { pattern: /aspnetcore|asp-validation|asp-for|asp-action/i, name: 'ASP.NET Core', type: '.NET Framework', confidence: 'High' },
        { pattern: /__dopostback|viewstate|__eventtarget/i, name: 'ASP.NET WebForms', type: '.NET Framework', confidence: 'High' },
        { pattern: /mvc\.jquery\.validate|jquery\.validate\.unobtrusive/i, name: 'ASP.NET MVC', type: '.NET Framework', confidence: 'High' },
        { pattern: /signalr/i, name: 'SignalR', type: '.NET Real-time', confidence: 'High' },
        { pattern: /telerik|kendo\.all|kendo-ui/i, name: 'Telerik/Kendo UI', type: '.NET UI Framework', confidence: 'High' },
        { pattern: /devexpress|dx-viewport/i, name: 'DevExpress', type: '.NET UI Framework', confidence: 'High' },
        { pattern: /syncfusion/i, name: 'Syncfusion', type: '.NET UI Framework', confidence: 'High' },
        { pattern: /radzen/i, name: 'Radzen', type: '.NET UI Framework', confidence: 'High' },

        // Java / Spring / JSF
        { pattern: /javax\.faces|jsf|primefaces/i, name: 'JavaServer Faces', type: 'Java Framework', confidence: 'High' },
        { pattern: /richfaces/i, name: 'RichFaces', type: 'Java JSF Library', confidence: 'High' },
        { pattern: /icefaces/i, name: 'ICEfaces', type: 'Java JSF Library', confidence: 'High' },
        { pattern: /spring|springframework/i, name: 'Spring Framework', type: 'Java Framework', confidence: 'High' },
        { pattern: /thymeleaf/i, name: 'Thymeleaf', type: 'Java Template Engine', confidence: 'High' },
        { pattern: /freemarker/i, name: 'FreeMarker', type: 'Java Template Engine', confidence: 'High' },
        { pattern: /velocity/i, name: 'Apache Velocity', type: 'Java Template Engine', confidence: 'Medium' },
        { pattern: /vaadin/i, name: 'Vaadin', type: 'Java Framework', confidence: 'High' },
        { pattern: /gwt|google web toolkit/i, name: 'Google Web Toolkit', type: 'Java Framework', confidence: 'High' },
        { pattern: /wicket/i, name: 'Apache Wicket', type: 'Java Framework', confidence: 'High' },
        { pattern: /struts/i, name: 'Apache Struts', type: 'Java Framework', confidence: 'High' },
        { pattern: /liferay/i, name: 'Liferay', type: 'Java Portal', confidence: 'High' },

        // Python
        { pattern: /django/i, name: 'Django', type: 'Python Framework', confidence: 'High' },
        { pattern: /flask/i, name: 'Flask', type: 'Python Framework', confidence: 'Medium' },
        { pattern: /jinja/i, name: 'Jinja2', type: 'Python Template Engine', confidence: 'High' },

        // Ruby
        { pattern: /turbo|stimulus/i, name: 'Hotwire (Rails)', type: 'Ruby Framework', confidence: 'High' },
        { pattern: /rails-ujs/i, name: 'Ruby on Rails', type: 'Ruby Framework', confidence: 'High' },

        // Other Backend & API
        { pattern: /swagger|openapi/i, name: 'Swagger/OpenAPI', type: 'API Documentation', confidence: 'High' },
        { pattern: /graphql/i, name: 'GraphQL', type: 'API', confidence: 'High' },
        { pattern: /socket\.io/i, name: 'Socket.IO', type: 'Real-time', confidence: 'High' },
        { pattern: /firebase/i, name: 'Firebase', type: 'Backend Service', confidence: 'High' },
        { pattern: /amplify/i, name: 'AWS Amplify', type: 'Backend Service', confidence: 'Medium' },
        { pattern: /supabase/i, name: 'Supabase', type: 'Backend Service', confidence: 'High' },
        { pattern: /hasura/i, name: 'Hasura', type: 'GraphQL Engine', confidence: 'High' },
    ],

    // Cookie patterns
    cookiePatterns: [
        { pattern: /PHPSESSID/i, name: 'PHP', type: 'Programming Language', confidence: 'High' },
        { pattern: /JSESSIONID/i, name: 'Java', type: 'Programming Language', confidence: 'High' },
        { pattern: /ASP\.NET_SessionId/i, name: 'ASP.NET', type: 'Web Framework', confidence: 'High' },
        { pattern: /_ga|_gid/i, name: 'Google Analytics', type: 'Analytics', confidence: 'High' },
        { pattern: /laravel_session/i, name: 'Laravel', type: 'Web Framework', confidence: 'High' },
        { pattern: /django/i, name: 'Django', type: 'Web Framework', confidence: 'Medium' },
        { pattern: /express[\.\-_]?sess/i, name: 'Express.js', type: 'Web Framework', confidence: 'Medium' },
    ]
};

class TechnologyDetectorService {
    // HTTPS agent that ignores SSL certificate errors (for internal network)
    private httpsAgent = new https.Agent({
        rejectUnauthorized: false // İç ağ için SSL doğrulamasını devre dışı bırak
    });

    constructor() {
        // No external dependencies needed
    }

    /**
     * Detect technologies using HTTP header and content analysis
     * Optimized for internal network usage
     */
    async detectTechnologies(targetUrl: string): Promise<DetectionResult> {
        try {
            console.log(`🔍 Starting technology detection for: ${targetUrl}`);

            // Use comprehensive HTTP analysis
            const technologies = await this.comprehensiveAnalysis(targetUrl);

            // Remove duplicates
            const uniqueTechnologies = this.removeDuplicates(technologies);

            console.log(`📊 Detected ${uniqueTechnologies.length} unique technologies`);

            return {
                technologies: uniqueTechnologies,
                url: targetUrl,
                detectionTime: new Date().toISOString()
            };

        } catch (error) {
            console.error('❌ Technology detection failed:', error);

            return {
                technologies: [],
                url: targetUrl,
                detectionTime: new Date().toISOString()
            };
        }
    }

    /**
     * Comprehensive technology analysis
     */
    private async comprehensiveAnalysis(targetUrl: string): Promise<TechnologyResult[]> {
        const technologies: TechnologyResult[] = [];

        try {
            console.log(`🌐 Fetching ${targetUrl}...`);

            const response = await axios.get(targetUrl, {
                timeout: 30000, // 30 seconds for slower internal servers
                maxRedirects: 10,
                validateStatus: () => true,
                httpsAgent: this.httpsAgent, // SSL sertifika hatalarını yoksay
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                }
            });

            console.log(`📡 Response status: ${response.status}`);

            const headers = response.headers;
            const html = typeof response.data === 'string' ? response.data : '';
            const cookies = headers['set-cookie'] || [];

            // 1. Analyze Server header
            this.analyzeServerHeader(headers.server, technologies);

            // 2. Analyze X-Powered-By header
            this.analyzeXPoweredBy(headers['x-powered-by'], technologies);

            // 3. Analyze other response headers
            this.analyzeResponseHeaders(headers, technologies);

            // 4. Analyze HTML content
            this.analyzeHtmlContent(html, technologies);

            // 5. Analyze meta tags
            this.analyzeMetaTags(html, technologies);

            // 6. Analyze script sources
            this.analyzeScriptSources(html, technologies);

            // 7. Analyze link tags (CSS)
            this.analyzeLinkTags(html, technologies);

            // 8. Analyze cookies
            this.analyzeCookies(cookies, technologies);

            // 9. Detect from response status and basic info
            this.detectFromStatusAndInfo(response, technologies);

            console.log(`📊 Comprehensive analysis found ${technologies.length} technology indicators`);

        } catch (error: any) {
            console.error('❌ Comprehensive analysis failed:', error.message || error);

            // Still try to add some info based on error type
            if (error.code === 'ECONNREFUSED') {
                console.log('⚠️ Connection refused - server may be down or blocked');
            } else if (error.code === 'ENOTFOUND') {
                console.log('⚠️ DNS resolution failed - hostname not found');
            } else if (error.code === 'ETIMEDOUT') {
                console.log('⚠️ Connection timed out - server may be slow or unreachable');
            }
        }

        return technologies;
    }

    /**
     * Analyze Server header
     */
    private analyzeServerHeader(server: string | undefined, technologies: TechnologyResult[]): void {
        if (!server) return;

        console.log(`🔍 Server header: ${server}`);

        for (const sig of TECHNOLOGY_SIGNATURES.webServers) {
            if (sig.pattern.test(server)) {
                const versionMatch = server.match(/[\d.]+/);
                technologies.push({
                    name: sig.name,
                    type: sig.type,
                    confidence: 'High',
                    version: versionMatch ? versionMatch[0] : undefined
                });
            }
        }

        // If no known server matched, add the raw server value
        if (technologies.filter(t => t.type === 'Web Server' || t.type === 'CDN').length === 0) {
            technologies.push({
                name: server,
                type: 'Web Server',
                confidence: 'Medium'
            });
        }
    }

    /**
     * Analyze X-Powered-By header
     */
    private analyzeXPoweredBy(poweredBy: string | undefined, technologies: TechnologyResult[]): void {
        if (!poweredBy) return;

        console.log(`🔍 X-Powered-By: ${poweredBy}`);

        for (const sig of TECHNOLOGY_SIGNATURES.languages) {
            if (sig.pattern.test(poweredBy)) {
                const versionMatch = sig.versionPattern ? poweredBy.match(sig.versionPattern) : poweredBy.match(/[\d.]+/);
                technologies.push({
                    name: sig.name,
                    type: sig.type,
                    confidence: 'High',
                    version: versionMatch ? versionMatch[1] || versionMatch[0] : undefined
                });
            }
        }
    }

    /**
     * Analyze other response headers
     */
    private analyzeResponseHeaders(headers: any, technologies: TechnologyResult[]): void {
        // X-AspNet-Version
        if (headers['x-aspnet-version']) {
            technologies.push({
                name: 'ASP.NET',
                type: 'Web Framework',
                confidence: 'High',
                version: headers['x-aspnet-version']
            });
        }

        // X-AspNetMvc-Version
        if (headers['x-aspnetmvc-version']) {
            technologies.push({
                name: 'ASP.NET MVC',
                type: 'Web Framework',
                confidence: 'High',
                version: headers['x-aspnetmvc-version']
            });
        }

        // X-Drupal-Cache
        if (headers['x-drupal-cache'] || headers['x-drupal-dynamic-cache']) {
            technologies.push({
                name: 'Drupal',
                type: 'CMS',
                confidence: 'High'
            });
        }

        // X-Generator
        if (headers['x-generator']) {
            technologies.push({
                name: headers['x-generator'],
                type: 'CMS/Generator',
                confidence: 'High'
            });
        }

        // X-Varnish
        if (headers['x-varnish']) {
            technologies.push({
                name: 'Varnish',
                type: 'Cache',
                confidence: 'High'
            });
        }

        // X-Cache
        if (headers['x-cache']) {
            const cacheHeader = headers['x-cache'].toLowerCase();
            if (cacheHeader.includes('cloudfront')) {
                technologies.push({
                    name: 'Amazon CloudFront',
                    type: 'CDN',
                    confidence: 'High'
                });
            }
        }

        // CF-Ray (Cloudflare)
        if (headers['cf-ray']) {
            technologies.push({
                name: 'Cloudflare',
                type: 'CDN/Security',
                confidence: 'High'
            });
        }

        // X-Amz headers (AWS)
        if (headers['x-amz-cf-id'] || headers['x-amz-request-id']) {
            technologies.push({
                name: 'Amazon Web Services',
                type: 'Hosting',
                confidence: 'High'
            });
        }
    }

    /**
     * Analyze HTML content for technology patterns
     */
    private analyzeHtmlContent(html: string, technologies: TechnologyResult[]): void {
        if (!html) return;

        for (const sig of TECHNOLOGY_SIGNATURES.htmlPatterns) {
            if (sig.pattern.test(html)) {
                technologies.push({
                    name: sig.name,
                    type: sig.type,
                    confidence: sig.confidence
                });
            }
        }
    }

    /**
     * Analyze meta tags
     */
    private analyzeMetaTags(html: string, technologies: TechnologyResult[]): void {
        if (!html) return;

        // Generator meta tag
        const generatorMatch = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
        if (generatorMatch) {
            technologies.push({
                name: generatorMatch[1],
                type: 'CMS/Generator',
                confidence: 'High'
            });
        }

        // Viewport (indicates mobile-responsive design)
        if (/<meta[^>]+name=["']viewport["']/i.test(html)) {
            technologies.push({
                name: 'Responsive Design',
                type: 'Design Pattern',
                confidence: 'High'
            });
        }
    }

    /**
     * Analyze script sources
     */
    private analyzeScriptSources(html: string, technologies: TechnologyResult[]): void {
        if (!html) return;

        const scriptMatches = html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi);
        for (const match of scriptMatches) {
            const src = match[1].toLowerCase();

            // Check known CDN patterns
            if (src.includes('jquery')) technologies.push({ name: 'jQuery', type: 'JavaScript Library', confidence: 'High' });
            if (src.includes('bootstrap')) technologies.push({ name: 'Bootstrap', type: 'UI Framework', confidence: 'High' });
            if (src.includes('react')) technologies.push({ name: 'React', type: 'JavaScript Framework', confidence: 'High' });
            if (src.includes('angular')) technologies.push({ name: 'Angular', type: 'JavaScript Framework', confidence: 'High' });
            if (src.includes('vue')) technologies.push({ name: 'Vue.js', type: 'JavaScript Framework', confidence: 'High' });
            if (src.includes('lodash')) technologies.push({ name: 'Lodash', type: 'JavaScript Library', confidence: 'High' });
            if (src.includes('moment')) technologies.push({ name: 'Moment.js', type: 'JavaScript Library', confidence: 'High' });
            if (src.includes('axios')) technologies.push({ name: 'Axios', type: 'JavaScript Library', confidence: 'High' });
            if (src.includes('gsap') || src.includes('tweenmax')) technologies.push({ name: 'GSAP', type: 'JavaScript Library', confidence: 'High' });
            if (src.includes('three')) technologies.push({ name: 'Three.js', type: 'JavaScript Library', confidence: 'Medium' });
            if (src.includes('d3')) technologies.push({ name: 'D3.js', type: 'JavaScript Library', confidence: 'Medium' });
            if (src.includes('chart')) technologies.push({ name: 'Chart.js', type: 'JavaScript Library', confidence: 'Medium' });
            if (src.includes('swiper')) technologies.push({ name: 'Swiper', type: 'JavaScript Library', confidence: 'High' });
            if (src.includes('slick')) technologies.push({ name: 'Slick Carousel', type: 'JavaScript Library', confidence: 'High' });
            if (src.includes('owl')) technologies.push({ name: 'Owl Carousel', type: 'JavaScript Library', confidence: 'High' });
            if (src.includes('lightbox')) technologies.push({ name: 'Lightbox', type: 'JavaScript Library', confidence: 'High' });
            if (src.includes('fancybox')) technologies.push({ name: 'Fancybox', type: 'JavaScript Library', confidence: 'High' });
        }
    }

    /**
     * Analyze link tags (CSS)
     */
    private analyzeLinkTags(html: string, technologies: TechnologyResult[]): void {
        if (!html) return;

        const linkMatches = html.matchAll(/<link[^>]+href=["']([^"']+)["']/gi);
        for (const match of linkMatches) {
            const href = match[1].toLowerCase();

            if (href.includes('bootstrap')) technologies.push({ name: 'Bootstrap', type: 'UI Framework', confidence: 'High' });
            if (href.includes('tailwind')) technologies.push({ name: 'Tailwind CSS', type: 'UI Framework', confidence: 'High' });
            if (href.includes('bulma')) technologies.push({ name: 'Bulma', type: 'UI Framework', confidence: 'High' });
            if (href.includes('materialize')) technologies.push({ name: 'Materialize', type: 'UI Framework', confidence: 'High' });
            if (href.includes('fontawesome') || href.includes('font-awesome')) technologies.push({ name: 'Font Awesome', type: 'Icon Library', confidence: 'High' });
            if (href.includes('fonts.googleapis.com')) technologies.push({ name: 'Google Fonts', type: 'Font', confidence: 'High' });
            if (href.includes('animate.css')) technologies.push({ name: 'Animate.css', type: 'CSS Library', confidence: 'High' });
        }
    }

    /**
     * Analyze cookies
     */
    private analyzeCookies(cookies: string[], technologies: TechnologyResult[]): void {
        if (!cookies || cookies.length === 0) return;

        const cookieString = cookies.join(' ');

        for (const sig of TECHNOLOGY_SIGNATURES.cookiePatterns) {
            if (sig.pattern.test(cookieString)) {
                technologies.push({
                    name: sig.name,
                    type: sig.type,
                    confidence: sig.confidence
                });
            }
        }
    }

    /**
     * Detect from response status and general info
     */
    private detectFromStatusAndInfo(response: any, technologies: TechnologyResult[]): void {
        // Check content type
        const contentType = response.headers['content-type'] || '';

        if (contentType.includes('application/json')) {
            technologies.push({
                name: 'JSON API',
                type: 'API',
                confidence: 'High'
            });
        }

        // Check if HTTPS
        if (response.config?.url?.startsWith('https://')) {
            technologies.push({
                name: 'HTTPS/SSL',
                type: 'Security',
                confidence: 'High'
            });
        }
    }

    /**
     * Remove duplicate technologies
     */
    private removeDuplicates(technologies: TechnologyResult[]): TechnologyResult[] {
        const seen = new Map<string, TechnologyResult>();

        for (const tech of technologies) {
            const key = `${tech.name.toLowerCase()}-${tech.type.toLowerCase()}`;
            const existing = seen.get(key);

            // Keep the one with higher confidence or version info
            if (!existing) {
                seen.set(key, tech);
            } else if (tech.version && !existing.version) {
                seen.set(key, tech);
            } else if (tech.confidence === 'High' && existing.confidence !== 'High') {
                seen.set(key, tech);
            }
        }

        return Array.from(seen.values());
    }

    /**
     * Cleanup resources
     */
    async destroy() {
        // No external resources to clean up
    }
}

// Export singleton instance
export const technologyDetectorService = new TechnologyDetectorService();
export { TechnologyResult, DetectionResult };
