package io.github.ashr123.hash.verifier;

import picocli.CommandLine;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.stream.Stream;

@CommandLine.Command(name = "java -jar hash-verifier.jar",
		mixinStandardHelpOptions = true,
		versionProvider = HashVerifier.class,
		description = "Verify or generate file's hash with given hash.")
public class HashVerifier implements CommandLine.IVersionProvider
{
	private HashVerifier()
	{
	}

	public static void main(String... args)
	{
		new CommandLine(HashVerifier.class).execute(args);
	}

	public static byte[] digest(Path path, MessageDigest messageDigest) throws IOException
	{
		try (SeekableByteChannel seekableByteChannel = Files.newByteChannel(path, EnumSet.of(StandardOpenOption.READ)))
		{
			final ByteBuffer buffer = ByteBuffer.allocateDirect(Math.toIntExact(Math.min(
							Integer.MAX_VALUE,
							Math.min(
									Runtime.getRuntime().maxMemory(),
									seekableByteChannel.size()
							)
					)))
					.order(ByteOrder.nativeOrder());
			while (seekableByteChannel.read(buffer) != -1)
			{
				buffer.flip();
				messageDigest.update(buffer);
				buffer.clear();
			}
		}
		return messageDigest.digest();
	}

	@CommandLine.Command(mixinStandardHelpOptions = true,
			versionProvider = HashVerifier.class,
			showDefaultValues = true,
			description = "Generates hash from file according to given hash algorithm.")
	public static void generateHashFromFile(
			@CommandLine.Parameters(paramLabel = "algorithm",
					converter = MessageDigestConverter.class,
					completionCandidates = AlgorithmsName.class,
					description = "Which hash algorithm to use? (values: ${COMPLETION-CANDIDATES})")
			MessageDigest algorithm,
			@CommandLine.Parameters(paramLabel = "pathToFile",
					converter = PathConverter.class,
					description = "Path to file for digestion.")
			Path pathToFile
	)
	{
		System.err.println("Generating hash...");
		try
		{
			System.out.println(HexFormat.of().formatHex(digest(pathToFile, algorithm)));
		} catch (IOException e)
		{
			//noinspection ThrowablePrintedToSystemOut
			System.err.println(e);
		}
	}

	@CommandLine.Command(mixinStandardHelpOptions = true,
			versionProvider = HashVerifier.class,
			description = "Verify file's hash with given hash.")
	public static void verifyHash(
			@CommandLine.Parameters(paramLabel = "algorithm",
					converter = MessageDigestConverter.class,
					completionCandidates = AlgorithmsName.class,
					description = "Which hash algorithm to use? (values: ${COMPLETION-CANDIDATES})")
			MessageDigest algorithm,
			@CommandLine.Parameters(paramLabel = "pathToFile",
					converter = PathConverter.class,
					description = "Path to file for digestion.")
			Path pathToFile,
			@CommandLine.Parameters(paramLabel = "hash",
					description = "Hash string to verify against.")
			String hash
	)
	{
		System.err.println("Starting hash verification...");
		try
		{
			System.out.println(MessageDigest.isEqual(
					digest(pathToFile, algorithm),
					HexFormat.of().parseHex(hash)
			));
		} catch (IOException e)
		{
			//noinspection ThrowablePrintedToSystemOut
			System.err.println(e);
		}
	}

	@Override
	public String[] getVersion()
	{
		return new String[]{"Hash Verifier v" + getClass().getPackage().getImplementationVersion()};
	}

	private static class MessageDigestConverter implements CommandLine.ITypeConverter<MessageDigest>
	{
		@Override
		public MessageDigest convert(String value) throws NoSuchAlgorithmException
		{
			return MessageDigest.getInstance(value);
		}
	}

	private static class PathConverter implements CommandLine.ITypeConverter<Path>
	{
		@Override
		public Path convert(String value) throws IOException
		{
			final Path path = Path.of(value);
			if (Files.notExists(path))
				throw new NoSuchFileException(value);
			if (Files.isDirectory(path))
				throw new IOException("Is a directory");
			return path;
		}
	}

	private static class AlgorithmsName implements Iterable<String>
	{
		@Override
		public Iterator<String> iterator()
		{
			final String simpleName = MessageDigest.class.getSimpleName();
			return Stream.of(Security.getProviders()).parallel().unordered()
					.map(Provider::getServices)
					.flatMap(Collection::parallelStream)
					.filter(service -> simpleName.equalsIgnoreCase(service.getType()))
					.map(Provider.Service::getAlgorithm)
					.sorted()
					.iterator();
		}
	}
}
