/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: ['@proofbook/crypto', '@proofbook/verifier'],
  webpack: (config, { isServer }) => {
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        net: false,
        tls: false,
        dns: false,
        crypto: false,
      };
    }
    return config;
  },
};

export default nextConfig;
