#include <sstream>
#include "teview.h"

using namespace BinaryNinja;
using namespace std;

static TEViewType* g_teViewType = nullptr;

void BinaryNinja::InitTEViewType()
{
    static TEViewType type;
    BinaryViewType::Register(&type);
    g_teViewType = &type;
}

TEView::TEView(BinaryView* bv, bool parseOnly) : BinaryView("TE", bv->GetFile(), bv), m_parseOnly(parseOnly)
{
    CreateLogger("BinaryView");
    m_logger = CreateLogger("BinaryView.TEView");
    m_backedByDatabase = bv->GetFile()->IsBackedByDatabase("TE");
}

bool TEView::Init()
{
    BinaryReader reader(GetParentView(), LittleEndian);
    struct TEImageHeader imageHeader;
    Ref<Platform> platform;

    try
    {
        // Read the TE image header
        imageHeader.magic = reader.Read16();
        imageHeader.machine = reader.Read16();
        imageHeader.numberOfSections = reader.Read8();
        imageHeader.subsystem = reader.Read8();
        imageHeader.strippedSize = reader.Read16();
        imageHeader.addressOfEntrypoint = reader.Read32();
        imageHeader.baseOfCode = reader.Read32();
        imageHeader.imageBase = reader.Read64();
        imageHeader.dataDirectory[0].virtualAddress = reader.Read32();
        imageHeader.dataDirectory[0].size = reader.Read32();
        imageHeader.dataDirectory[1].virtualAddress = reader.Read32();
        imageHeader.dataDirectory[1].size = reader.Read32();

        m_logger->LogDebug(
            "TEImageHeader:\n"
            "\tmagic:                           0x%04x\n"
            "\tmachine:                         0x%04x\n"
            "\tnumberOfSections:                0x%02x\n"
            "\tsubsystem:                       0x%02x\n"
            "\tstrippedSize:                    0x%04x\n"
            "\taddressOfEntrypoint:             0x%08x\n"
            "\tbaseOfCode:                      0x%08x\n"
            "\timageBase:                       0x%016x\n"
            "\tdataDirectory[0].virtualAddress: 0x%08x\n"
            "\tdataDirectory[0].size:           0x%08x\n"
            "\tdataDirectory[1].virtualAddress: 0x%08x\n"
            "\tdataDirectory[1].size:           0x%08x\n",
            imageHeader.magic,
            imageHeader.machine,
            imageHeader.numberOfSections,
            imageHeader.subsystem,
            imageHeader.strippedSize,
            imageHeader.addressOfEntrypoint,
            imageHeader.baseOfCode,
            imageHeader.imageBase,
            imageHeader.dataDirectory[0].virtualAddress,
            imageHeader.dataDirectory[0].size,
            imageHeader.dataDirectory[1].virtualAddress,
            imageHeader.dataDirectory[1].size
        );

        // Save offset so we can make a read-only segment over the headers
        uint64_t headerSegmentSize = reader.GetOffset();

        // Read TE section headers
        for (uint32_t i = 0; i < imageHeader.numberOfSections; i++) {
            TEImageSectionHeader section;
            section.name = reader.ReadString(8);
            section.Misc.virtualSize = reader.Read32();
            section.virtualAddress = reader.Read32();
            section.sizeOfRawData = reader.Read32();
            section.pointerToRawData = reader.Read32();
            section.pointerToRelocations = reader.Read32();
            section.pointerToLineNumbers = reader.Read32();
            section.numberOfRelocations = reader.Read16();
            section.numberOfLineNumbers = reader.Read16();
            section.characteristics = reader.Read32();

            m_logger->LogDebug(
                "TEImageSectionHeader[%i]\n"
                "\tname: %s\n"
                "\tMisc.virtualSize: %08x\n"
                "\tvirtualAddress: %08x\n"
                "\tsizeOfRawData: %08x\n"
                "\tpointerToRawData: %08x\n"
                "\tpointerToRelocations: %08x\n"
                "\tpointerToLineNumbers: %08x\n"
                "\tnumberOfRelocations: %04x\n"
                "\tnumberOfLineNumbers: %04x\n"
                "\tcharacteristics: %08x\n",
                i,
                section.name.c_str(),
                section.Misc.virtualSize,
                section.virtualAddress,
                section.sizeOfRawData,
                section.pointerToRawData,
                section.pointerToRelocations,
                section.pointerToLineNumbers,
                section.numberOfRelocations,
                section.numberOfLineNumbers,
                section.characteristics
            );

            m_sections.push_back(section);
        }

        auto settings = GetLoadSettings(GetTypeName());
        if (settings && settings->Contains("loader.imageBase") && settings->Contains("loader.architecture"))
        {
            m_imageBase = settings->Get<uint64_t>("loader.imageBase", this);
            Ref<Architecture> arch = Architecture::GetByName(settings->Get<string>("loader.architecture", this));
			if (!m_arch || (arch && (arch->GetName() != m_arch->GetName())))
				m_arch = arch;
        } else {
            m_imageBase = imageHeader.imageBase;
        }

        // TODO: verify that there aren't other architectures. I know there is a RISC-V port in progress
        if (!m_arch)
        {
            switch (imageHeader.machine)
            {
            case IMAGE_FILE_MACHINE_I386:
                m_is64 = false;
                break;
            case IMAGE_FILE_MACHINE_AMD64:
                m_is64 = true;
                break;
            case IMAGE_FILE_MACHINE_ARM64:
                m_is64 = true;
                break;
            default:
                LogError("TE architecture '0x%x' is not supported", imageHeader.machine);
                return false;
            }
        }

        platform = g_teViewType->GetPlatform(imageHeader.subsystem, m_arch);
        if (!platform)
            platform = m_arch->GetStandalonePlatform();

		SetDefaultPlatform(platform);
		SetDefaultArchitecture(platform->GetArchitecture());
        if (!m_arch)
            m_arch = platform->GetArchitecture();

        // Create a segment for the header so that it can be viewed
        AddAutoSegment(m_imageBase, headerSegmentSize, 0, headerSegmentSize, SegmentReadable);
        for (uint32_t i = 0; i < imageHeader.numberOfSections; i++) {
            auto section = m_sections[i];

            uint32_t flags = 0;
            if (section.characteristics & 0x80000000)
				flags |= SegmentWritable;
			if (section.characteristics & 0x40000000)
				flags |= SegmentReadable;
			if (section.characteristics & 0x20000000)
				flags |= SegmentExecutable;
			if (section.characteristics & 0x80)
				flags |= SegmentContainsData;
			if (section.characteristics & 0x40)
				flags |= SegmentContainsData;
			if (section.characteristics & 0x20)
				flags |= SegmentContainsCode;

            AddAutoSegment(
                section.virtualAddress + m_imageBase,
                section.sizeOfRawData,
                section.virtualAddress,
                section.sizeOfRawData,
                flags
            );

            BNSectionSemantics semantics = DefaultSectionSemantics;
            uint32_t pFlags = flags & 0x7;
			if (pFlags == (SegmentReadable | SegmentExecutable))
				semantics = ReadOnlyCodeSectionSemantics;
			else if (pFlags == SegmentReadable)
				semantics = ReadOnlyDataSectionSemantics;
			else if (pFlags == (SegmentReadable | SegmentWritable))
				semantics = ReadWriteDataSectionSemantics;

            AddAutoSection(section.name, section.virtualAddress + m_imageBase, section.sizeOfRawData, semantics);
        }

        // Finished for parse only mode
        if (m_parseOnly)
            return true;

        m_entryPoint = imageHeader.imageBase + imageHeader.addressOfEntrypoint;
        AddEntryPointForAnalysis(platform, m_entryPoint);
    }
    catch (std::exception& e)
    {
        m_logger->LogError("Failed to parse TE headers: %s\n", e.what());
        return false;
    }

    return true;
}

uint64_t TEView::PerformGetEntryPoint() const
{
	return m_imageBase + m_entryPoint;
}


size_t TEView::PerformGetAddressSize() const
{
	return m_is64 ? 8 : 4;
}

TEViewType::TEViewType() : BinaryViewType("TE", "TE")
{
	m_logger = LogRegistry::CreateLogger("BinaryView");
}

Ref<BinaryView> TEViewType::Create(BinaryView* bv)
{
	try
	{
		return new TEView(bv);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}

Ref<BinaryView> TEViewType::Parse(BinaryView* bv)
{
	try
	{
		return new TEView(bv, true);
	}
	catch (std::exception& e)
	{
		m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}

bool TEViewType::IsTypeValidForData(BinaryView* bv)
{
    DataBuffer sig = bv->ReadBuffer(0, 2);
    if (sig.GetLength() != 2)
        return false;

    // Check the VZ signature
    if (memcmp(sig.GetData(), "VZ", 2))
        return false;

    return true;
}

Ref<Settings> TEViewType::GetLoadSettingsForData(BinaryView *bv)
{
    Ref<BinaryView> viewRef = Parse(bv);
    if (!viewRef || !viewRef->Init()) {
		m_logger->LogError("View type '%s' could not be created", GetName().c_str());
		return nullptr;
    }

	Ref<Settings> settings = GetDefaultLoadSettingsForData(viewRef);

	// specify default load settings that can be overridden
	vector<string> overrides = {"loader.architecture", "loader.imageBase", "loader.platform"};
	if (!viewRef->IsRelocatable())
		settings->UpdateProperty("loader.imageBase", "message", "Note: File indicates image is not relocatable.");

	for (const auto& override : overrides)
	{
		if (settings->Contains(override))
			settings->UpdateProperty(override, "readOnly", false);
	}

    return settings;
}