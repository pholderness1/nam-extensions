package nl.idfocus.nam.util;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Our logformatter class takes care of single-line logging, as opposed to the default double-line logging which is the default for the IDP. <br/>
 * The static {@link #getConsoleLogger(String)} method returns a console logger for IDP logging. 
 * @author mvreijn
 *
 */
public final class LogFormatter extends SimpleFormatter 
{

    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    @Override
    public String format(LogRecord record) {
        StringBuilder sb = new StringBuilder();

        sb.append(new Date(record.getMillis()))
            .append(" ")
            .append( record.getSourceClassName() )
            .append(" ")
            .append( record.getSourceMethodName() )
            .append(" ")
            .append(record.getLevel().getLocalizedName())
            .append(": ")
            .append(formatMessage(record))
            .append(LINE_SEPARATOR);

        if (record.getThrown() != null) {
            try {
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw);
                record.getThrown().printStackTrace(pw);
                pw.close();
                sb.append(sw.toString());
            } catch (Exception ex) {
                // ignore
            }
        }

        return sb.toString();
    }

    /**
     * Create a logger with a console handler and single-line log formatting for the given classname. 
     * @param clazz the classname as derived from {@code class.getName()}
     * @return a {@link #java.util.logging.Logger Logger} object
     */
    public static Logger getConsoleLogger( String clazz )
    {
    	final Logger logger = Logger.getLogger( clazz );
		Handler hd = new ConsoleHandler();
		hd.setFormatter( new LogFormatter() );
		hd.setLevel(Level.ALL);
		logger.setUseParentHandlers(false);
		logger.addHandler(hd);
		logger.setLevel(Level.ALL);
		return logger;
    }

    /**
     * Set the given logger and its handlers to log at level {@link java.util.logging.Level#ALL}, i.e. log everything.
     * @param logger
     */
    public static void setLoggerDebugMode( Logger logger )
    {
        for( Handler hd : logger.getHandlers() )
            hd.setLevel(Level.ALL);
        logger.setLevel(Level.ALL);
    }
}