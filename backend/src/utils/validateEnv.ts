export const validateEnv = () => {
  const requiredVars = [
    'DATABASE_URL',
    'ZAP_PROXY_URL'
  ];

  const missingVars = requiredVars.filter(varName => !process.env[varName]);

  if (missingVars.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missingVars.join(', ')}`
    );
  }
};
