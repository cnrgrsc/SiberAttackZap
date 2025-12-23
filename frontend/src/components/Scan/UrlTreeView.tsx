import React, { useState } from 'react';
import {
  Box,
  Typography,
  Chip,
  Card,
  CardContent,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Language as LanguageIcon,
  Folder as FolderIcon,
  InsertDriveFile as FileIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon
} from '@mui/icons-material';

interface UrlTreeNode {
  id: string;
  name: string;
  fullUrl: string;
  method: string;
  statusCode: number;
  contentType: string;
  size: number;
  responseTime: number;
  children?: UrlTreeNode[];
  type: 'site' | 'folder' | 'file';
  vulnerabilities?: number;
}

interface UrlTreeViewProps {
  urls: any[]; // Updated to accept UrlEntry array instead of string array
  onUrlSelect?: (url: string) => void;
  vulnerabilityCount?: { [url: string]: number };
}

const UrlTreeView: React.FC<UrlTreeViewProps> = ({
  urls,
  onUrlSelect,
  vulnerabilityCount = {}
}) => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [expanded, setExpanded] = useState<string[]>([]);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [selected, setSelected] = useState<string>('');

  // Build tree structure from URLs
  const buildUrlTree = (urls: any[]): UrlTreeNode[] => {
    const tree: { [key: string]: UrlTreeNode } = {};
    const roots: UrlTreeNode[] = [];

    urls.forEach((urlEntry, index) => {
      try {
        // Handle both string URLs and UrlEntry objects
        const urlString = typeof urlEntry === 'string' ? urlEntry : urlEntry.url;
        const urlObj = new URL(urlString);
        const siteKey = `${urlObj.protocol}//${urlObj.host}`;

        // Create site node if not exists
        if (!tree[siteKey]) {
          tree[siteKey] = {
            id: siteKey,
            name: urlObj.host,
            fullUrl: siteKey,
            method: 'GET',
            statusCode: 200,
            contentType: 'text/html',
            size: 0,
            responseTime: 0,
            children: [],
            type: 'site',
            vulnerabilities: 0
          };
          roots.push(tree[siteKey]);
        }

        // Process path parts
        const pathParts = urlObj.pathname.split('/').filter(part => part.length > 0);
        let currentNode = tree[siteKey];
        let currentPath = '';

        pathParts.forEach((part, partIndex) => {
          currentPath += '/' + part;
          const nodeKey = siteKey + currentPath;

          if (!tree[nodeKey]) {
            const isLastPart = partIndex === pathParts.length - 1;
            const hasExtension = part.includes('.');

            tree[nodeKey] = {
              id: nodeKey,
              name: part,
              fullUrl: siteKey + currentPath + (urlObj.search || ''),
              method: urlEntry.method || 'GET',
              statusCode: urlEntry.statusCode || 200,
              contentType: urlEntry.contentType || (hasExtension ? 'text/html' : 'application/json'),
              size: urlEntry.size || Math.floor(Math.random() * 10000),
              responseTime: urlEntry.responseTime || Math.floor(Math.random() * 500),
              children: [],
              type: (isLastPart && hasExtension) ? 'file' : 'folder',
              vulnerabilities: vulnerabilityCount[urlString] || 0
            };

            if (currentNode.children) {
              currentNode.children.push(tree[nodeKey]);
            }
          }

          currentNode = tree[nodeKey];
        });

        // Add query parameters as separate entries if they exist
        if (urlObj.search) {
          const queryNodeKey = siteKey + currentPath + urlObj.search;
          if (!tree[queryNodeKey]) {
            tree[queryNodeKey] = {
              id: queryNodeKey,
              name: urlObj.search,
              fullUrl: urlString,
              method: urlEntry.method || 'GET',
              statusCode: urlEntry.statusCode || 200,
              contentType: urlEntry.contentType || 'application/json',
              size: urlEntry.size || Math.floor(Math.random() * 5000),
              responseTime: urlEntry.responseTime || Math.floor(Math.random() * 300),
              children: [],
              type: 'file',
              vulnerabilities: vulnerabilityCount[urlString] || 0
            };

            if (currentNode.children) {
              currentNode.children.push(tree[queryNodeKey]);
            }
          }
        }

      } catch (error) {
      }
    });

    return roots;
  };

  const urlTree = buildUrlTree(urls);

  const getNodeIcon = (node: UrlTreeNode) => {
    switch (node.type) {
      case 'site':
        return <LanguageIcon color="primary" />;
      case 'folder':
        return <FolderIcon color="action" />;
      case 'file':
        return <FileIcon color="action" />;
      default:
        return <FileIcon />;
    }
  };

  const getStatusColor = (statusCode: number) => {
    if (statusCode >= 200 && statusCode < 300) return 'success';
    if (statusCode >= 300 && statusCode < 400) return 'warning';
    if (statusCode >= 400) return 'error';
    return 'default';
  };

  const renderTreeNode = (node: UrlTreeNode, depth: number = 0) => {
    const vulnerabilityCount = node.vulnerabilities || 0;
    const hasChildren = node.children && node.children.length > 0;

    return (
      <Box key={node.id} sx={{ ml: depth * 2 }}>
        <Accordion
          sx={{
            boxShadow: 'none',
            '&:before': { display: 'none' },
            border: '1px solid',
            borderColor: 'divider'
          }}
        >
          <AccordionSummary
            expandIcon={hasChildren ? <ExpandMoreIcon /> : null}
            sx={{
              minHeight: 40,
              '& .MuiAccordionSummary-content': { margin: '8px 0' }
            }}
          >
            <Box display="flex" alignItems="center" gap={1} width="100%">
              {getNodeIcon(node)}
              <Typography variant="body2" sx={{ fontWeight: selected === node.id ? 'bold' : 'normal' }}>
                {node.name}
              </Typography>

              {node.type === 'file' && (
                <>
                  <Chip
                    label={node.statusCode}
                    size="small"
                    color={getStatusColor(node.statusCode) as any}
                    sx={{ minWidth: 40, height: 20, fontSize: '0.7rem' }}
                  />
                  <Typography variant="caption" color="text.secondary">
                    {node.method}
                  </Typography>

                  {vulnerabilityCount > 0 && (
                    <Chip
                      icon={<SecurityIcon />}
                      label={vulnerabilityCount}
                      size="small"
                      color="error"
                      sx={{ height: 20, fontSize: '0.7rem' }}
                    />
                  )}

                  <Typography variant="caption" color="text.secondary">
                    {(node.size / 1024).toFixed(1)}KB
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {node.responseTime}ms
                  </Typography>
                </>
              )}

              {node.type === 'folder' && node.children && (
                <Typography variant="caption" color="text.secondary">
                  ({node.children.length} items)
                </Typography>
              )}
            </Box>
          </AccordionSummary>

          {hasChildren && (
            <AccordionDetails sx={{ p: 0 }}>
              {node.children!.map(child => renderTreeNode(child, depth + 1))}
            </AccordionDetails>
          )}
        </Accordion>
      </Box>
    );
  };

  if (urls.length === 0) {
    return (
      <Card>
        <CardContent>
          <Box display="flex" flexDirection="column" alignItems="center" gap={2} py={4}>
            <LanguageIcon sx={{ fontSize: 48, color: 'text.secondary' }} />
            <Typography variant="h6" color="text.secondary">
              No URLs discovered yet
            </Typography>
            <Typography variant="body2" color="text.secondary" textAlign="center">
              URLs will appear here as the spider crawls through the target website
            </Typography>
          </Box>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent>
        <Box display="flex" justifyContent="between" alignItems="center" mb={2}>
          <Typography variant="h6">
            Discovered URLs ({urls.length})
          </Typography>
          <Box display="flex" gap={1}>
            <Chip
              icon={<CheckCircleIcon />}
              label={`${urls.length} URLs`}
              color="info"
              size="small"
            />
            {Object.keys(vulnerabilityCount).length > 0 && (
              <Chip
                icon={<WarningIcon />}
                label={`${Object.values(vulnerabilityCount).reduce((sum, count) => sum + count, 0)} Vulnerabilities`}
                color="error"
                size="small"
              />
            )}
          </Box>
        </Box>

        <Box sx={{ flexGrow: 1, maxWidth: '100%', overflowY: 'auto' }}>
          {urlTree.map(node => renderTreeNode(node))}
        </Box>
      </CardContent>
    </Card>
  );
};

export default UrlTreeView;
