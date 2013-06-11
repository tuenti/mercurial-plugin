package hudson.plugins.mercurial;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Hudson;
import hudson.model.Node;
import hudson.model.TaskListener;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Mercurial repository that serves as a cache to hg operations in the Hudson cluster.
 *
 * <p>
 * This substantially improves the performance by reducing the amount of data that needs to be transferred.
 * One cache will be built on the Hudson master, then per-slave cache is cloned from there.
 *
 * @see HUDSON-4794: manages repository caches.
 * @author Jesse Glick
 */
class Cache {
    /**
     * The remote source repository that this repository is caching.
     */
    private final String remote;

    /**
     * Hashed value of {@link #remote} that only contains characters that are safe as a directory name.
     */
    private final String hash;

    /**
     * Mutual exclusion to the access to the cache.
     */
    private final ReentrantLock masterLock = new ReentrantLock(true);
    private final Map<String, ReentrantLock> slaveNodesLocksMap = new HashMap<String, ReentrantLock>();

    private Cache(String remote, String hash) {
        this.remote = remote;
        this.hash = hash;
    }

    private static final Map<String, Cache> CACHES = new HashMap<String, Cache>();

    public synchronized static @NonNull Cache fromURL(String remote) {
        String h = hashSource(remote);
        Cache cache = CACHES.get(h);
        if (cache == null) {
            CACHES.put(h, cache = new Cache(remote, h));
        }
        return cache;
    }

    /**
     * Gets a lock for the given slave node.
     * @param node Name of the slave node.
     * @return The {@link ReentrantLock} instance.
     */
    private synchronized ReentrantLock getLockForSlaveNode(String node) {
        ReentrantLock lock = slaveNodesLocksMap.get(node);
        if (lock == null) {
            slaveNodesLocksMap.put(node, lock = new ReentrantLock(true));
        }

        return lock;
    }


    /**
     * Returns a local hg repository cache of the remote repository specified in the given {@link MercurialSCM}
     * on the given {@link Node}, fully updated to the tip of the current remote repository.
     *
     * @param node
     *      The node that gets a local cached repository.
     *
     * @return
     *      The file path on the {@code node} to the local repository cache, cloned off from the master cache.
     */
    @CheckForNull FilePath repositoryCache(MercurialSCM config, Node node, Launcher launcher, TaskListener listener, boolean fromPolling)
            throws IOException, InterruptedException {

        // Always update master cache first.
        Node master = Hudson.getInstance();
        FilePath masterCaches = master.getRootPath().child("hgcache");
        FilePath masterCache = masterCaches.child(hash);
        Launcher masterLauncher = node == master ? launcher : master.createLauncher(listener);

        // hg invocation on master
        // do we need to pass in EnvVars from a build too?
        HgExe masterHg = new HgExe(config,masterLauncher,master,listener,new EnvVars());

        // Lock the block used to verify we end up having a cloned repo in the master,
        // whether if it was previously cloned in a different build or if it's
        // going to be cloned right now.
        masterLock.lockInterruptibly();
        listener.getLogger().println("Acquired master cache lock.");
        try {
            if (masterCache.isDirectory()) {
                if (MercurialSCM.joinWithPossibleTimeout(masterHg.pull(config.getBranch()).pwd(masterCache), true, listener) != 0) {
                    listener.error("Failed to update " + masterCache);
                    return null;
                }
            } else {
                masterCaches.mkdirs();
                if (MercurialSCM.joinWithPossibleTimeout(masterHg.clone("--noupdate", remote, masterCache.getRemote()), true, listener) != 0) {
                    listener.error("Failed to clone " + remote + " in master");
                    return null;
                }
            }
        } finally {
                masterLock.unlock();
                listener.getLogger().println("Master cache lock released.");
        }
        if (node == master) {
            return masterCache;
        }

        FilePath localCaches = node.getRootPath().child("hgcache");
        FilePath localCache = localCaches.child(hash);

        // Pull from master
        HgExe slaveHg = new HgExe(config,launcher,node,listener,new EnvVars());
        ReentrantLock slaveLock = getLockForSlaveNode(node.getNodeName());
        slaveLock.lockInterruptibly();
        try {
            listener.getLogger().println("Acquired slave node cache lock for node " + node.getNodeName() + ".");
            // Need to clone entire repo.
            if(localCache.isDirectory()) {
                if (MercurialSCM.joinWithPossibleTimeout(slaveHg.pull(config.getBranch()).pwd(localCache), true, listener) != 0) {
                    listener.error("Failed to update " + localCache);
                    return null;
                }
            } else {
                localCaches.mkdirs();
                if (MercurialSCM.joinWithPossibleTimeout(slaveHg.clone("--noupdate", remote, localCache.getRemote()), true, listener) != 0) {
                    listener.error("Failed to lcone " +  remote + " in " + node.getNodeName());
                    return null;
                }
            }
        } finally {
            slaveLock.unlock();
            listener.getLogger().println("Slave node cache lock released for node " + node.getNodeName() + ".");
        }

        return localCache;
    }


    /**
     * Hash a URL into a string that only contains characters that are safe as directory names.
     */
    static String hashSource(String source) {
        if (!source.endsWith("/")) {
            source += "/";
        }
        Matcher m = Pattern.compile(".+[/]([^/:]+)(:\\d+)?[/]?").matcher(source);
        BigInteger hash;
        try {
            hash = new BigInteger(1, MessageDigest.getInstance("SHA-1").digest(source.getBytes("UTF-8")));
        } catch (Exception x) {
            throw new AssertionError(x);
        }
        return String.format("%040X%s", hash, m.matches() ? "-" + m.group(1) : "");
    }

}
