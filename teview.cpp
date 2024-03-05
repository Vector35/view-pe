#include <sstream>
#include "teview.h"

using namespace BinaryNinja;
using namespace std;

static TEViewType* g_teViewType = nullptr;

void TEView::ReadTEImageHeader(BinaryReader& reader, struct TEImageHeader& header)
{
    header.magic = reader.Read16();
    header.machine = reader.Read16();
    header.numberOfSections = reader.Read8();
    header.subsystem = reader.Read8();
    header.strippedSize = reader.Read16();
    header.addressOfEntrypoint = reader.Read32();
    header.baseOfCode = reader.Read32();
    header.imageBase = reader.Read64();
    header.dataDirectory[0].virtualAddress = reader.Read32();
    header.dataDirectory[0].size = reader.Read32();
    header.dataDirectory[1].virtualAddress = reader.Read32();
    header.dataDirectory[1].size = reader.Read32();

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
        header.magic,
        header.machine,
        header.numberOfSections,
        header.subsystem,
        header.strippedSize,
        header.addressOfEntrypoint,
        header.baseOfCode,
        header.imageBase,
        header.dataDirectory[0].virtualAddress,
        header.dataDirectory[0].size,
        header.dataDirectory[1].virtualAddress,
        header.dataDirectory[1].size
    );
}

void TEView::ReadTEImageSectionHeaders(BinaryReader& reader, uint32_t numSections)
{
    for (uint32_t i = 0; i < numSections; i++) {
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
}

void TEView::CreateSections()
{
    for (size_t i = 0; i < m_sections.size(); i++) {
        auto section = m_sections[i];
        uint32_t flags = 0;
        if (section.characteristics & EFI_TE_MEM_WRITE)
            flags |= SegmentWritable;
        if (section.characteristics & EFI_TE_MEM_READ)
            flags |= SegmentReadable;
        if (section.characteristics & EFI_TE_MEM_EXECUTE)
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
}

void TEView::AssignHeaderTypes()
{
    StructureBuilder dataDirectoryBuilder;
    dataDirectoryBuilder.AddMember(Type::IntegerType(4, false), "VirtualAddress");
    dataDirectoryBuilder.AddMember(Type::IntegerType(4, false), "Size");
    auto dataDirectoryStruct = dataDirectoryBuilder.Finalize();
    auto dataDirectoryType = Type::StructureType(dataDirectoryStruct);

    StructureBuilder headerBuilder;
    headerBuilder.AddMember(Type::IntegerType(2, false), "Signature");
    headerBuilder.AddMember(Type::IntegerType(2, false), "Machine");
    headerBuilder.AddMember(Type::IntegerType(1, false), "NumberOfSections");
    headerBuilder.AddMember(Type::IntegerType(1, false), "Subsystem");
    headerBuilder.AddMember(Type::IntegerType(2, false), "StrippedSize");
    headerBuilder.AddMember(Type::IntegerType(4, false), "AddressOfEntryPoint");
    headerBuilder.AddMember(Type::IntegerType(4, false), "BaseOfCode");
    headerBuilder.AddMember(Type::IntegerType(8, false), "ImageBase");
    headerBuilder.AddMember(Type::ArrayType(dataDirectoryType, 2), "DataDirectory");

    auto headerStruct = headerBuilder.Finalize();
    auto headerType = Type::StructureType(headerStruct);
    QualifiedName headerName = string("TE_Header");
    string headerTypeId = Type::GenerateAutoTypeId("te", headerName);
    QualifiedName headerTypeName = DefineType(headerTypeId, headerName, headerType);
    DefineDataVariable(m_imageBase, Type::NamedType(this, headerTypeName));

    StructureBuilder sectionBuilder;
    sectionBuilder.AddMember(Type::IntegerType(8, false), "Name");
    sectionBuilder.AddMember(Type::IntegerType(4, false), "PhysicalAddress");
    sectionBuilder.AddMember(Type::IntegerType(4, false), "VirtualAddress");
    sectionBuilder.AddMember(Type::IntegerType(4, false), "SizeOfRawData");
    sectionBuilder.AddMember(Type::IntegerType(4, false), "PointerToRawData");
    sectionBuilder.AddMember(Type::IntegerType(4, false), "PointerToRelocations");
    sectionBuilder.AddMember(Type::IntegerType(4, false), "PointerToLinenumbers");
    sectionBuilder.AddMember(Type::IntegerType(2, false), "NumberOfRelocations");
    sectionBuilder.AddMember(Type::IntegerType(2, false), "NumberOfLinenumbers");
    sectionBuilder.AddMember(Type::IntegerType(4, false), "Characteristics");
    auto sectionStruct = sectionBuilder.Finalize();
    auto sectionType = Type::StructureType(sectionStruct);
    for (size_t i = 0; i < m_sections.size(); i++)
    {
        QualifiedName sectionName = string("TE_Section_Header_") + to_string(i);
        string sectionTypeId = Type::GenerateAutoTypeId("te", sectionName);
        QualifiedName sectionTypeName = DefineType(sectionTypeId, sectionName, sectionType);
        DefineDataVariable(
            m_imageBase + EFI_TE_IMAGE_HEADER_SIZE + (EFI_TE_SECTION_HEADER_SIZE * i),
            Type::NamedType(this, sectionTypeName)
        );
    }
}

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
    struct TEImageHeader header;
    Ref<Platform> platform;
    Ref<Architecture> arch;

    try
    {
        // Read image header and section headers
        ReadTEImageHeader(reader, header);
        ReadTEImageSectionHeaders(reader, header.numberOfSections);

        // Save offset so we can make a read-only segment over the headers
        uint64_t headerSegmentSize = reader.GetOffset();

        // TODO rework how we handle user overrides and derive platform / arch

        // Handle user overrides
        auto settings = GetLoadSettings(GetTypeName());
        if (settings && settings->Contains("loader.imageBase") && settings->Contains("loader.architecture"))
        {
            m_imageBase = settings->Get<uint64_t>("loader.imageBase", this);
            arch = Architecture::GetByName(settings->Get<string>("loader.architecture", this));
        } else {
            m_imageBase = header.imageBase;
        }

        // Attempt to identify platform from metadata
		map<string, Ref<Metadata>> metadataMap = {
			{"Machine",               new Metadata((uint64_t) header.machine)},
			{"Subsystem",             new Metadata((uint64_t) header.subsystem)},
		};
		Ref<Metadata> metadata = new Metadata(metadataMap);
		platform = g_teViewType->RecognizePlatform(header.machine, LittleEndian, GetParentView(), metadata);
        if (platform && !arch)
            arch = platform->GetArchitecture();

        if (!arch)
        {
            switch (header.machine)
            {
            case IMAGE_FILE_MACHINE_I386:
                platform = Platform::GetByName("efi-pei-x86");
                m_is64 = false;
                break;
            case IMAGE_FILE_MACHINE_AMD64:
                platform = Platform::GetByName("x86_64");
                m_is64 = true;
                break;
            case IMAGE_FILE_MACHINE_ARM64:
                platform = Platform::GetByName("aarch64");
                m_is64 = true;
                break;
            default:
                LogError("TE architecture '0x%x' is not supported", header.machine);
                return false;
            }

            arch = platform->GetArchitecture();
        }
        else
        {
            platform = arch->GetStandalonePlatform();
        }

		SetDefaultPlatform(platform);
		SetDefaultArchitecture(arch);

        // Create a segment for the header so that it can be viewed and create sections
        AddAutoSegment(m_imageBase, headerSegmentSize, 0, headerSegmentSize, SegmentReadable);
        CreateSections();
        AssignHeaderTypes();

        // Finished for parse only mode
        if (m_parseOnly)
            return true;

        m_entryPoint = header.imageBase + header.addressOfEntrypoint;
		DefineAutoSymbol(new Symbol(FunctionSymbol, "ModuleEntryPoint", m_entryPoint));
        // TODO: apply prototype
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

    // TODO: more validation

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